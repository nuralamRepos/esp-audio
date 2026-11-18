#!/usr/bin/env python3
"""
esp-telephone audio bridge & backend (Native Android App Architecture).
Connects Multiple Android App Callers -> Single ESP32 Hardware Listener.

System Roles:
  - Android Applications: UI, native audio hardware (AEC/NS/AGC), call controls, permissions.
  - Custom Backend: Authentication, atomic call locking (single-active-call policy), token issuance.
  - LiveKit Cloud: Real-time WebRTC media server for voice conference.
  - Media Gateway: Linux bridge converting ESP32 lightweight UDP audio <-> LiveKit room audio.
  - ESP32: Lightweight audio hardware (16kHz mSBC) + physical button. (No WebRTC on chip).
"""

import asyncio
import json
import os
import signal
import socket
import struct
import sys
import time
from collections import deque
from urllib.parse import urlparse, parse_qs
import hmac
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- Configuration

_envfile = os.path.join(HERE, ".env")
if os.path.exists(_envfile):
    with open(_envfile) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ[_k.strip()] = _v.strip()

DEVICE_RATE = 16000
CHANNELS = 1
FRAME_MS = 20
FRAME_SAMPLES = (DEVICE_RATE * FRAME_MS) // 1000  # 320 samples = 640 bytes
FRAME_BYTES = FRAME_SAMPLES * 2

UDP_PORT = int(os.environ.get("UDP_PORT", 8081))
HTTP_PORT = int(os.environ.get("PORT", os.environ.get("HTTP_PORT", 8080)))
DEVICE_ID = os.environ.get("DEVICE_ID", "esp32-home")

LIVEKIT_URL = os.environ.get("LIVEKIT_URL", "")
LIVEKIT_KEY = os.environ.get("LIVEKIT_API_KEY", os.environ.get("LIVEKIT_KEY", ""))
LIVEKIT_SECRET = os.environ.get("LIVEKIT_API_SECRET", os.environ.get("LIVEKIT_SECRET", ""))
ROOM_NAME = os.environ.get("LIVEKIT_ROOM", "landline")

# Security and Policy
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "nuralam9922").strip()
MAX_CALL_DURATION_SEC = int(os.environ.get("MAX_CALL_DURATION_SEC", 1800))  # 30m max call
RING_TIMEOUT_SEC = int(os.environ.get("RING_TIMEOUT_SEC", 45))  # 45s ringing timeout
MAX_CALLS_PER_MIN = int(os.environ.get("MAX_CALLS_PER_MIN", 6))
MAX_REQ_PER_MIN = int(os.environ.get("MAX_REQ_PER_MIN", 60))

# Protocol Opcodes (ESP32 <-> Gateway)
PKT_CONTROL     = 0x01
PKT_AUDIO       = 0x02
PKT_PING        = 0x03
PKT_PONG        = 0x04
PKT_CALL_RING   = 0x10
PKT_CALL_ACCEPT = 0x11
PKT_CALL_END    = 0x12
PKT_CALL_BUSY   = 0x13

# ---------------------------------------------------------------- Rate Limiter & Auth

class RateLimiter:
    """Sliding-window rate limiter per client IP."""
    def __init__(self):
        self.general_limits = {}
        self.call_limits = {}

    def check(self, ip: str, is_call_op: bool = False) -> tuple[bool, str]:
        now = time.time()
        q = self.general_limits.setdefault(ip, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= MAX_REQ_PER_MIN:
            return False, f"Too many requests ({len(q)}/min). Limit is {MAX_REQ_PER_MIN}/min."
        q.append(now)

        if is_call_op:
            cq = self.call_limits.setdefault(ip, deque())
            while cq and now - cq[0] > 60:
                cq.popleft()
            if len(cq) >= MAX_CALLS_PER_MIN:
                return False, f"Too many call attempts ({len(cq)}/min). Limit is {MAX_CALLS_PER_MIN}/min."
            cq.append(now)

        return True, ""

RATE_LIMITER = RateLimiter()

def check_auth(headers: dict, query_params: dict) -> bool:
    """Verifies that the request comes from an authorized Android application."""
    if not AUTH_TOKEN:
        return True
    token = headers.get("x-auth-token")
    if not token:
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
        elif auth_hdr:
            token = auth_hdr.strip()
    if not token:
        token = query_params.get("auth", [""])[0] or query_params.get("token", [""])[0]

    if not token:
        return False
    return hmac.compare_digest(token.strip(), AUTH_TOKEN)

# ---------------------------------------------------------------- Audio Filter & AGC

class AudioProcessor:
    """Bandpass filter (300-3400 Hz) + smooth AGC + soft limiter for downlink audio."""
    def __init__(self, sample_rate=16000):
        self.sr = sample_rate
        self._init_filters()
        self.gain = 1.0
        self.target_peak = 18000.0

    def _init_filters(self):
        # HPF 300 Hz @ 16 kHz
        self.hp_b = np.array([0.92006, -1.84013, 0.92006], dtype=np.float32)
        self.hp_a = np.array([1.0, -1.83373, 0.84653], dtype=np.float32)
        self.hp_z = np.zeros(2, dtype=np.float32)

        # LPF 3400 Hz @ 16 kHz
        self.lp_b = np.array([0.24524, 0.49048, 0.24524], dtype=np.float32)
        self.lp_a = np.array([1.0, -0.40795, 0.38890], dtype=np.float32)
        self.lp_z = np.zeros(2, dtype=np.float32)

    def process_pcm16(self, pcm_bytes: bytes) -> bytes:
        if not pcm_bytes:
            return b""
        samples = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32)

        # 1. HPF (300 Hz)
        y_hp = np.empty_like(samples)
        for i, x in enumerate(samples):
            y = self.hp_b[0] * x + self.hp_z[0]
            self.hp_z[0] = self.hp_b[1] * x - self.hp_a[1] * y + self.hp_z[1]
            self.hp_z[1] = self.hp_b[2] * x - self.hp_a[2] * y
            y_hp[i] = y

        # 2. LPF (3400 Hz)
        y_lp = np.empty_like(y_hp)
        for i, x in enumerate(y_hp):
            y = self.lp_b[0] * x + self.lp_z[0]
            self.lp_z[0] = self.lp_b[1] * x - self.lp_a[1] * y + self.lp_z[1]
            self.lp_z[1] = self.lp_b[2] * x - self.lp_a[2] * y
            y_lp[i] = y

        # 3. AGC
        cur_peak = float(np.max(np.abs(y_lp))) if len(y_lp) > 0 else 0.0
        if cur_peak > 100.0:
            target_g = self.target_peak / cur_peak
            if target_g < self.gain:
                self.gain = 0.8 * self.gain + 0.2 * target_g
            else:
                self.gain = 0.995 * self.gain + 0.005 * target_g
            self.gain = max(0.2, min(self.gain, 3.5))

        out = y_lp * self.gain

        # 4. Soft Limiter
        limit = 32000.0
        mask = np.abs(out) > limit
        if np.any(mask):
            out[mask] = np.sign(out[mask]) * (limit + (32760.0 - limit) * np.tanh((np.abs(out[mask]) - limit) / (32760.0 - limit)))

        out = np.clip(out, -32767.0, 32767.0).astype(np.int16)
        return out.tobytes()

# ---------------------------------------------------------------- Backend Call State & Telemetry

class DeviceCallLock:
    """
    Enforces atomic single-active-call policy.
    One ESP32 listener <-> Only one active Android caller at a time.
    """
    def __init__(self):
        self.device_id = DEVICE_ID
        self.device_addr = None
        self.state = "IDLE"  # IDLE, RINGING, IN_CALL
        self.active_call_id = None
        self.active_caller_id = None
        self.call_start_time = None
        self.ring_start_time = None
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.rx_frames = 0
        self.tx_frames = 0
        self.dropped_frames = 0
        self.rx_dbfs = -120.0
        self.tx_dbfs = -120.0
        self.start_time = time.time()

    def as_dict(self):
        call_dur = 0
        if self.state == "IN_CALL" and self.call_start_time:
            call_dur = int(time.time() - self.call_start_time)
        return {
            "device_id": self.device_id,
            "online": self.device_addr is not None,
            "state": self.state.lower(),
            "availability": "available" if self.state == "IDLE" else "busy",
            "active_call_id": self.active_call_id,
            "active_caller_id": self.active_caller_id,
            "call_duration_sec": call_dur,
            "max_call_duration_sec": MAX_CALL_DURATION_SEC,
            "rx_dbfs": round(self.rx_dbfs, 1),
            "tx_dbfs": round(self.tx_dbfs, 1),
            "uptime_sec": int(time.time() - self.start_time),
        }

STATS = DeviceCallLock()

def compute_dbfs(pcm: bytes):
    if not pcm or len(pcm) < 2:
        return -120.0
    arr = np.frombuffer(pcm, dtype=np.int16).astype(np.float32)
    peak = float(np.max(np.abs(arr)))
    if peak <= 1.0:
        return -120.0
    return max(-120.0, 20.0 * np.log10(peak / 32767.0))

# ---------------------------------------------------------------- UDP Link with ESP32 Hardware

class UdpLinkProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_audio_rx, on_call_accept, on_call_end):
        self.on_audio_rx = on_audio_rx
        self.on_call_accept = on_call_accept
        self.on_call_end = on_call_end
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        print(f"[udp] listening on port {UDP_PORT}", flush=True)

    def datagram_received(self, data, addr):
        if not data:
            return
        kind = data[0]

        if kind == PKT_CONTROL:
            if STATS.device_addr != addr:
                print(f"[udp] ESP32 hardware discovered at {addr[0]}:{addr[1]}", flush=True)
                STATS.device_addr = addr
            self.transport.sendto(bytes([PKT_CONTROL]) + b"HERE", addr)

        elif kind == PKT_PING:
            STATS.device_addr = addr
            self.transport.sendto(bytes([PKT_PONG]), addr)

        elif kind == PKT_AUDIO:
            STATS.device_addr = addr
            pcm = data[1:]
            STATS.rx_bytes += len(pcm)
            STATS.rx_frames += 1
            STATS.rx_dbfs = compute_dbfs(pcm)
            self.on_audio_rx(pcm)

        elif kind == PKT_CALL_ACCEPT:
            print("[udp] ESP32 physical button pressed: ACCEPT CALL", flush=True)
            self.on_call_accept()

        elif kind == PKT_CALL_END:
            print("[udp] ESP32 physical button pressed: HANG UP", flush=True)
            self.on_call_end(notify_esp=False)

    def send_audio(self, pcm: bytes):
        if not STATS.device_addr or not self.transport:
            return
        self.transport.sendto(bytes([PKT_AUDIO]) + pcm, STATS.device_addr)
        STATS.tx_bytes += len(pcm)
        STATS.tx_frames += 1
        STATS.tx_dbfs = compute_dbfs(pcm)

    def ring_device(self):
        if STATS.device_addr and self.transport:
            self.transport.sendto(bytes([PKT_CALL_RING]), STATS.device_addr)

    def send_call_end(self):
        if STATS.device_addr and self.transport:
            self.transport.sendto(bytes([PKT_CALL_END]), STATS.device_addr)

    def send_call_busy(self):
        if STATS.device_addr and self.transport:
            self.transport.sendto(bytes([PKT_CALL_BUSY]), STATS.device_addr)

# ---------------------------------------------------------------- Downlink Pacer Queue

class DownlinkPacer:
    """Buffers incoming WebRTC frames and drains them at strict 20ms intervals."""
    def __init__(self, udp_link: UdpLinkProtocol):
        self.udp_link = udp_link
        self.queue = asyncio.Queue(maxsize=15)
        self.processor = AudioProcessor(DEVICE_RATE)
        self.task = None
        self._running = False

    def start(self):
        self._running = True
        self.task = asyncio.create_task(self._pacer_loop())

    def stop(self):
        self._running = False
        if self.task:
            self.task.cancel()
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self.processor = AudioProcessor(DEVICE_RATE)

    def push(self, pcm640: bytes):
        if not self._running:
            return
        if self.queue.full():
            try:
                self.queue.get_nowait()
                STATS.dropped_frames += 1
            except asyncio.QueueEmpty:
                pass
        self.queue.put_nowait(pcm640)

    async def _pacer_loop(self):
        next_tick = time.monotonic()
        while self._running:
            try:
                next_tick += 0.020
                delay = next_tick - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
                else:
                    next_tick = time.monotonic()

                try:
                    chunk = self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    if STATS.state == "IN_CALL":
                        chunk = b"\x00" * FRAME_BYTES
                    else:
                        continue

                filtered = self.processor.process_pcm16(chunk)
                self.udp_link.send_audio(filtered)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[pacer] error: {e}", flush=True)

# ---------------------------------------------------------------- LiveKit Media Gateway

class LiveKitSession:
    """Server-side participant that bridges ESP32 audio <-> LiveKit Room."""
    def __init__(self, udp_link: UdpLinkProtocol, pacer: DownlinkPacer, on_empty_room=None):
        self.udp_link = udp_link
        self.pacer = pacer
        self.on_empty_room = on_empty_room
        self.room = None
        self.source = None
        self.tasks = []
        self._audio_q = asyncio.Queue(maxsize=20)
        self._pumps = {}

    async def start(self, url: str, token: str):
        from livekit import rtc
        self.room = rtc.Room()

        def _cancel_pump(identity):
            task = self._pumps.pop(identity, None)
            if task and not task.done():
                task.cancel()

        @self.room.on("track_subscribed")
        def on_track(track, publication, participant):
            if track.kind != rtc.TrackKind.KIND_AUDIO:
                return
            who = participant.identity
            _cancel_pump(who)
            print(f"[lk] subscribed to audio from Android caller: {who}", flush=True)
            self._pumps[who] = asyncio.create_task(self._pump_down(track, who))

        @self.room.on("track_unsubscribed")
        def on_unsub(track, publication, participant):
            if track.kind == rtc.TrackKind.KIND_AUDIO:
                print(f"[lk] unsubscribed from {participant.identity}", flush=True)
                _cancel_pump(participant.identity)

        @self.room.on("participant_disconnected")
        def on_part_left(participant):
            _cancel_pump(participant.identity)
            remotes = [p for p in self.room.remote_participants.values() if p.identity != participant.identity]
            print(f"[lk] caller left: {participant.identity} (remaining remote: {len(remotes)})", flush=True)
            if len(remotes) == 0:
                print("[lk] room is empty: all callers disconnected", flush=True)
                if self.on_empty_room:
                    self.on_empty_room()

        print(f"[lk] connecting to {url} room={ROOM_NAME}...", flush=True)
        await self.room.connect(url, token)
        print("[lk] connected successfully to LiveKit Cloud!", flush=True)

        self.source = rtc.AudioSource(DEVICE_RATE, CHANNELS)
        track = rtc.LocalAudioTrack.create_audio_track("earbud-mic", self.source)
        await self.room.local_participant.publish_track(
            track, rtc.TrackPublishOptions(source=rtc.TrackSource.SOURCE_MICROPHONE)
        )
        print("[lk] earbud microphone published to room", flush=True)
        self.tasks.append(asyncio.create_task(self._publish_task()))

    def push_uplink(self, pcm: bytes):
        if not self.source:
            return
        if self._audio_q.full():
            try:
                self._audio_q.get_nowait()
                STATS.dropped_frames += 1
            except asyncio.QueueEmpty:
                pass
        self._audio_q.put_nowait(pcm)

    async def _publish_task(self):
        from livekit import rtc
        while True:
            pcm = await self._audio_q.get()
            try:
                frame = rtc.AudioFrame(
                    data=pcm,
                    sample_rate=DEVICE_RATE,
                    num_channels=CHANNELS,
                    samples_per_channel=len(pcm) // 2,
                )
                await self.source.capture_frame(frame)
            except Exception as e:
                print(f"[lk] capture_frame: {e}", flush=True)

    async def _pump_down(self, track, who):
        from livekit import rtc
        stream = rtc.AudioStream(track, sample_rate=DEVICE_RATE,
                                 num_channels=CHANNELS, frame_size_ms=FRAME_MS)
        buf = bytearray()
        try:
            async for ev in stream:
                buf.extend(ev.frame.data)
                while len(buf) >= FRAME_BYTES:
                    chunk = bytes(buf[:FRAME_BYTES])
                    del buf[:FRAME_BYTES]
                    self.pacer.push(chunk)
        except asyncio.CancelledError:
            pass
        finally:
            print(f"[lk] downlink closed for {who}", flush=True)
            try:
                await stream.aclose()
            except Exception:
                pass

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        self.tasks.clear()
        for p in self._pumps.values():
            p.cancel()
        self._pumps.clear()
        while not self._audio_q.empty():
            try:
                self._audio_q.get_nowait()
            except asyncio.QueueEmpty:
                break
        if self.room:
            try:
                await self.room.disconnect()
            except Exception:
                pass
            self.room = None
        self.source = None

# ---------------------------------------------------------------- Telephone Manager & Call Locking

class TelephoneManager:
    def __init__(self):
        self.udp = None
        self.pacer = None
        self.livekit = None
        self._watchdog_task = None

    async def init(self):
        loop = asyncio.get_running_loop()
        self.udp = UdpLinkProtocol(
            on_audio_rx=self.on_device_audio,
            on_call_accept=self.on_button_accept,
            on_call_end=self.on_button_hangup
        )
        await loop.create_datagram_endpoint(lambda: self.udp, local_addr=("0.0.0.0", UDP_PORT))

        self.pacer = DownlinkPacer(self.udp)
        self.pacer.start()

        self.livekit = LiveKitSession(
            self.udp,
            self.pacer,
            on_empty_room=self.on_remote_empty
        )
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())

    async def _watchdog_loop(self):
        """Monitors ringing timeouts and maximum call duration to preserve LiveKit quota."""
        while True:
            try:
                await asyncio.sleep(2)
                now = time.time()
                # 1. Ringing timeout (45s)
                if STATS.state == "RINGING" and STATS.ring_start_time:
                    if now - STATS.ring_start_time > RING_TIMEOUT_SEC:
                        print(f"[watchdog] Call ringing timed out after {RING_TIMEOUT_SEC}s without answer -> auto-cancelling", flush=True)
                        self.on_button_hangup(notify_esp=True)
                # 2. Maximum call duration watchdog (30 min)
                elif STATS.state == "IN_CALL" and STATS.call_start_time:
                    dur = now - STATS.call_start_time
                    if dur > MAX_CALL_DURATION_SEC:
                        print(f"[watchdog] Max call duration reached ({dur:.0f}s >= {MAX_CALL_DURATION_SEC}s) -> auto-hanging up to preserve quota", flush=True)
                        self.on_button_hangup(notify_esp=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[watchdog] error: {e}", flush=True)

    def on_remote_empty(self):
        print("[call] caller disconnected from LiveKit room -> releasing call lock", flush=True)
        self.on_button_hangup(notify_esp=True)

    async def start_call_session(self):
        if self.livekit.room is None:
            from livekit import api
            token = (api.AccessToken(LIVEKIT_KEY, LIVEKIT_SECRET)
                     .with_identity("esp32-bridge")
                     .with_grants(api.VideoGrants(room_join=True, room=ROOM_NAME))
                     .to_jwt())
            print("[livekit] on-demand connect to room (0 quota used while idle)", flush=True)
            await self.livekit.start(LIVEKIT_URL, token)

    async def stop_call_session(self):
        if self.livekit.room is not None:
            print("[livekit] disconnected from room (preserving quota)", flush=True)
            await self.livekit.stop()

    def on_device_audio(self, pcm: bytes):
        if STATS.state == "IN_CALL":
            self.livekit.push_uplink(pcm)

    def on_button_accept(self):
        print("[call] answered on hardware; connecting audio on-demand", flush=True)
        STATS.state = "IN_CALL"
        STATS.call_start_time = time.time()
        STATS.ring_start_time = None
        asyncio.create_task(self.start_call_session())

    def on_button_hangup(self, notify_esp=True):
        print("[call] call ended: releasing listener lock", flush=True)
        STATS.state = "IDLE"
        STATS.active_call_id = None
        STATS.active_caller_id = None
        STATS.call_start_time = None
        STATS.ring_start_time = None
        if notify_esp:
            self.udp.send_call_end()
        asyncio.create_task(self.stop_call_session())

# ---------------------------------------------------------------- Native REST API

def generate_caller_token(caller_id: str):
    """Generates a short-lived token strictly for the authenticated Android caller."""
    from livekit import api
    token = (api.AccessToken(LIVEKIT_KEY, LIVEKIT_SECRET)
             .with_identity(caller_id)
             .with_grants(api.VideoGrants(room_join=True, room=ROOM_NAME, can_publish=True, can_subscribe=True))
             .to_jwt())
    return {"url": LIVEKIT_URL, "token": token, "room": ROOM_NAME}

def make_json_response(status_code: int, status_text: str, data: dict, extra_headers: list = None) -> bytes:
    body = json.dumps(data, indent=2).encode("utf-8")
    hdrs = [
        f"HTTP/1.1 {status_code} {status_text}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Headers: Content-Type, Authorization, X-Auth-Token",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS",
        "Connection: close",
    ]
    if extra_headers:
        hdrs.extend(extra_headers)
    return ("\r\n".join(hdrs) + "\r\n\r\n").encode("utf-8") + body

async def run_http_server(mgr: TelephoneManager):
    async def handler(reader, writer):
        try:
            req = await reader.read(4096)
            if not req:
                return

            peername = writer.get_extra_info("peername")
            client_ip = peername[0] if peername else "unknown"

            raw_text = req.decode(errors="ignore")
            lines = raw_text.split("\r\n")
            first_line = lines[0].split(" ") if lines else []
            method = first_line[0] if len(first_line) > 0 else "GET"
            full_path = first_line[1] if len(first_line) > 1 else "/"

            headers = {}
            body_start = -1
            for i, h in enumerate(lines[1:], 1):
                if not h:
                    body_start = i + 1
                    break
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            req_body_text = "\r\n".join(lines[body_start:]) if body_start != -1 else ""

            if "x-forwarded-for" in headers:
                client_ip = headers["x-forwarded-for"].split(",")[0].strip()

            parsed_url = urlparse(full_path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)

            # 1. CORS Preflight
            if method == "OPTIONS":
                resp = (
                    b"HTTP/1.1 204 No Content\r\n"
                    b"Access-Control-Allow-Origin: *\r\n"
                    b"Access-Control-Allow-Headers: Content-Type, Authorization, X-Auth-Token\r\n"
                    b"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                    b"Access-Control-Max-Age: 86400\r\n"
                    b"Connection: close\r\n\r\n"
                )
                writer.write(resp)
                await writer.drain()
                return

            # 2. Rate Limiter
            is_call_op = path in ("/call/start", "/token")
            allowed, limit_msg = RATE_LIMITER.check(client_ip, is_call_op=is_call_op)
            if not allowed:
                resp = make_json_response(429, "Too Many Requests", {
                    "error": "too_many_requests",
                    "detail": limit_msg
                }, ["Retry-After: 60"])
                writer.write(resp)
                await writer.drain()
                return

            # 3. Routes

            # Health Check / Keepalive
            if path == "/ping":
                resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong"

            # Device Availability (Single-Listener Status)
            elif path in ("/status", "/devices"):
                if not check_auth(headers, query_params):
                    resp = make_json_response(401, "Unauthorized", {
                        "error": "unauthorized",
                        "detail": "Android application authentication token required"
                    }, ["WWW-Authenticate: Bearer"])
                else:
                    data = [STATS.as_dict()] if path == "/devices" else STATS.as_dict()
                    resp = make_json_response(200, "OK", data)

            # Call Reservation & Initiation (Atomic Call Lock)
            elif path == "/call/start":
                if not check_auth(headers, query_params):
                    resp = make_json_response(401, "Unauthorized", {
                        "error": "unauthorized",
                        "detail": "Android application authentication token required"
                    }, ["WWW-Authenticate: Bearer"])
                elif STATS.state in ("IN_CALL", "RINGING"):
                    # Single-active-call policy: Lock held by another caller
                    resp = make_json_response(486, "Busy Here", {
                        "error": "busy",
                        "detail": "ESP32 listener is currently on another call",
                        "active_call_id": STATS.active_call_id,
                        "active_caller_id": STATS.active_caller_id
                    })
                else:
                    # Parse caller identity from Android request body
                    caller_id = "android-caller"
                    try:
                        req_json = json.loads(req_body_text) if req_body_text else {}
                        caller_id = req_json.get("caller_id", "android-caller")
                    except Exception:
                        pass

                    call_id = f"call_{int(time.time())}_{caller_id}"
                    print(f"[call] Reserved for caller '{caller_id}' (call_id={call_id})", flush=True)

                    # Acquire atomic lock
                    STATS.state = "RINGING"
                    STATS.active_call_id = call_id
                    STATS.active_caller_id = caller_id
                    STATS.ring_start_time = time.time()

                    # Trigger physical ESP32 ringing and start gateway session
                    mgr.udp.ring_device()
                    asyncio.create_task(mgr.start_call_session())

                    # Issue short-lived credentials for the authorized Android caller
                    cred = generate_caller_token(caller_id)
                    resp = make_json_response(200, "OK", {
                        "call_id": call_id,
                        "caller_id": caller_id,
                        "target_device": DEVICE_ID,
                        "room": cred["room"],
                        "livekit_url": cred["url"],
                        "token": cred["token"],
                        "expires_in": 3600
                    })

            # Call Termination
            elif path in ("/call/end", "/hangup"):
                if not check_auth(headers, query_params):
                    resp = make_json_response(401, "Unauthorized", {
                        "error": "unauthorized",
                        "detail": "Android application authentication token required"
                    }, ["WWW-Authenticate: Bearer"])
                else:
                    mgr.on_button_hangup()
                    resp = make_json_response(200, "OK", {"status": "ended", "device": DEVICE_ID})

            # Root & Unknown Routes -> API Service Info (NO WEB UI)
            else:
                resp = make_json_response(200, "OK", {
                    "service": "esp-telephone-backend",
                    "mode": "native-android-api-only",
                    "version": "1.0.0",
                    "device": DEVICE_ID,
                    "status": "online"
                })

            writer.write(resp)
            await writer.drain()
        except Exception as e:
            print(f"[http] error processing request: {e}", flush=True)
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "0.0.0.0", HTTP_PORT)
    return server

# ---------------------------------------------------------------- Entrypoint

async def main():
    mgr = TelephoneManager()
    await mgr.init()

    STATS.state = "IDLE"
    print(f"[backend] ESP32 Internet Calling Gateway started on port {HTTP_PORT}", flush=True)
    print(f"[backend] Single-Listener Policy active (MAX_CALL_DURATION={MAX_CALL_DURATION_SEC}s, RING_TIMEOUT={RING_TIMEOUT_SEC}s)", flush=True)
    print(f"[backend] Protected API (AUTH_TOKEN={'configured' if AUTH_TOKEN else 'disabled'}). No web calling permitted.", flush=True)

    http = await run_http_server(mgr)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop_event.set)

    await stop_event.wait()
    print("[backend] shutting down...", flush=True)
    await mgr.livekit.stop()
    mgr.pacer.stop()

if __name__ == "__main__":
    asyncio.run(main())
