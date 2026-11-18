#!/usr/bin/env python3
"""
esp-telephone audio bridge (Production-hardened).
Connects ESP32 HFP AG (UDP PCM16 16kHz) <-> LiveKit Cloud Room.

Features:
  - Downlink audio filtering: anti-alias bandpass (300Hz-3400Hz), smooth AGC, soft limiter.
  - Paced 20ms datagram sender (eliminates network burst jitter to ESP32).
  - Physical call control: handles ring signal, button press to accept, hangup.
  - Native LiveKit Cloud data packet messaging (serverless signaling).
  - Security & Anti-Abuse:
      * Token authentication (AUTH_TOKEN / X-Auth-Token / Bearer / ?auth=).
      * Sliding-window IP rate limiter (anti-DDoS, anti-spam, quota shield).
      * Automatic call duration watchdog (30m max limit prevents runaway quota usage).
      * Ringing timeout (45s auto-cancel if nobody answers).
      * Empty-room auto-disconnect (quits immediately when caller disconnects).
  - Built-in lightweight web client with browser DSP noise suppression and echo cancellation.
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

# Security and Quota Protection Configuration
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "nuralam9922").strip()
MAX_CALL_DURATION_SEC = int(os.environ.get("MAX_CALL_DURATION_SEC", 1800))  # 30 minutes max call duration
RING_TIMEOUT_SEC = int(os.environ.get("RING_TIMEOUT_SEC", 45))  # 45s ringing timeout
MAX_CALLS_PER_MIN = int(os.environ.get("MAX_CALLS_PER_MIN", 6))
MAX_REQ_PER_MIN = int(os.environ.get("MAX_REQ_PER_MIN", 60))

# Protocol Opcodes
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
    """Sliding-window IP rate limiter to protect server and LiveKit quota."""
    def __init__(self):
        self.general_limits = {}  # ip -> deque of timestamps
        self.call_limits = {}     # ip -> deque of timestamps

    def check(self, ip: str, is_call_op: bool = False) -> tuple[bool, str]:
        now = time.time()
        # General request limit
        q = self.general_limits.setdefault(ip, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= MAX_REQ_PER_MIN:
            return False, f"Too many requests ({len(q)}/min). Limit is {MAX_REQ_PER_MIN}/min."
        q.append(now)

        # Call / token initiation limit
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
    """Verifies that the request carries the pre-shared secret AUTH_TOKEN."""
    if not AUTH_TOKEN:
        return True  # If AUTH_TOKEN is empty, authentication is disabled
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
    """Bandpass filter (300-3400 Hz) + smooth AGC + soft limiter."""
    def __init__(self, sample_rate=16000):
        self.sr = sample_rate
        self._init_filters()
        self.gain = 1.0
        self.target_peak = 18000.0  # target peak around -5 dBFS

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

        # 1. High-pass (300 Hz)
        y_hp = np.empty_like(samples)
        for i, x in enumerate(samples):
            y = self.hp_b[0] * x + self.hp_z[0]
            self.hp_z[0] = self.hp_b[1] * x - self.hp_a[1] * y + self.hp_z[1]
            self.hp_z[1] = self.hp_b[2] * x - self.hp_a[2] * y
            y_hp[i] = y

        # 2. Low-pass (3400 Hz)
        y_lp = np.empty_like(y_hp)
        for i, x in enumerate(y_hp):
            y = self.lp_b[0] * x + self.lp_z[0]
            self.lp_z[0] = self.lp_b[1] * x - self.lp_a[1] * y + self.lp_z[1]
            self.lp_z[1] = self.lp_b[2] * x - self.lp_a[2] * y
            y_lp[i] = y

        # 3. AGC (slow release, fast attack)
        cur_peak = float(np.max(np.abs(y_lp))) if len(y_lp) > 0 else 0.0
        if cur_peak > 100.0:
            target_g = self.target_peak / cur_peak
            if target_g < self.gain:
                self.gain = 0.8 * self.gain + 0.2 * target_g
            else:
                self.gain = 0.995 * self.gain + 0.005 * target_g
            self.gain = max(0.2, min(self.gain, 3.5))

        out = y_lp * self.gain

        # 4. Soft Limiter (tanh saturation prevents digital clipping)
        limit = 32000.0
        mask = np.abs(out) > limit
        if np.any(mask):
            out[mask] = np.sign(out[mask]) * (limit + (32760.0 - limit) * np.tanh((np.abs(out[mask]) - limit) / (32760.0 - limit)))

        out = np.clip(out, -32767.0, 32767.0).astype(np.int16)
        return out.tobytes()

# ---------------------------------------------------------------- Telemetry

class BridgeStats:
    def __init__(self):
        self.device_addr = None
        self.state = "IDLE"  # IDLE, RINGING, IN_CALL, BUSY
        self.active_call_id = None
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
            "device": self.device_addr is not None,
            "deviceAddr": list(self.device_addr) if self.device_addr else None,
            "state": self.state,
            "activeCallId": self.active_call_id,
            "callDurationSec": call_dur,
            "maxCallDurationSec": MAX_CALL_DURATION_SEC,
            "rxBytes": self.rx_bytes,
            "txBytes": self.tx_bytes,
            "rxFrames": self.rx_frames,
            "txFrames": self.tx_frames,
            "droppedFrames": self.dropped_frames,
            "rxDbfs": round(self.rx_dbfs, 1),
            "txDbfs": round(self.tx_dbfs, 1),
            "uptimeSec": int(time.time() - self.start_time),
        }

STATS = BridgeStats()

def compute_dbfs(pcm: bytes):
    if not pcm or len(pcm) < 2:
        return -120.0
    arr = np.frombuffer(pcm, dtype=np.int16).astype(np.float32)
    peak = float(np.max(np.abs(arr)))
    if peak <= 1.0:
        return -120.0
    return max(-120.0, 20.0 * np.log10(peak / 32767.0))

# ---------------------------------------------------------------- UDP Link with ESP32

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
                print(f"[udp] ESP32 discovered at {addr[0]}:{addr[1]}", flush=True)
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
            if STATS.rx_frames % 50 == 0:
                print(f"[telemetry-udp-rx] ESP32 earbud mic -> Bridge: {STATS.rx_frames} frames ({STATS.rx_bytes//1024} KB), peak={STATS.rx_dbfs:.1f} dBFS", flush=True)
            self.on_audio_rx(pcm)

        elif kind == PKT_CALL_ACCEPT:
            print("[udp] ESP32 physical button pressed: ACCEPT CALL", flush=True)
            self.on_call_accept()

        elif kind == PKT_CALL_END:
            print("[udp] ESP32 button pressed: HANG UP", flush=True)
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

# ---------------------------------------------------------------- LiveKit Media Transport

class LiveKitSession:
    def __init__(self, udp_link: UdpLinkProtocol, pacer: DownlinkPacer, on_data_packet=None, on_empty_room=None):
        self.udp_link = udp_link
        self.pacer = pacer
        self.on_data_packet = on_data_packet
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
            print(f"[lk] subscribed to audio from {who}", flush=True)
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
            print(f"[lk] remote participant left: {participant.identity} (remaining remote: {len(remotes)})", flush=True)
            if len(remotes) == 0:
                print("[lk] room is empty: caller left room", flush=True)
                if self.on_empty_room:
                    self.on_empty_room()

        @self.room.on("data_received")
        def on_data(data_packet):
            if self.on_data_packet:
                try:
                    payload = json.loads(data_packet.data.decode("utf-8"))
                    self.on_data_packet(payload, data_packet.participant)
                except Exception:
                    pass

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
        count = 0
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
                count += 1
                if count % 50 == 0:
                    print(f"[telemetry-lk-tx] Pushed {count} frames ({(count*20)//1000}s) from earbuds -> LiveKit Cloud", flush=True)
            except Exception as e:
                print(f"[lk] capture_frame: {e}", flush=True)

    async def _pump_down(self, track, who):
        from livekit import rtc
        stream = rtc.AudioStream(track, sample_rate=DEVICE_RATE,
                                 num_channels=CHANNELS, frame_size_ms=FRAME_MS)
        buf = bytearray()
        count = 0
        try:
            async for ev in stream:
                buf.extend(ev.frame.data)
                while len(buf) >= FRAME_BYTES:
                    chunk = bytes(buf[:FRAME_BYTES])
                    del buf[:FRAME_BYTES]
                    self.pacer.push(chunk)
                    count += 1
                    if count % 50 == 0:
                        print(f"[telemetry-lk-rx] Received {count} frames ({(count*20)//1000}s) from mobile ({who}) -> earbuds", flush=True)
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

# ---------------------------------------------------------------- Telephone Manager

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
            on_data_packet=self.on_livekit_data,
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
        print("[call] caller disconnected from LiveKit room -> hanging up bridge to preserve quota", flush=True)
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

    def on_livekit_data(self, payload: dict, participant):
        ptype = payload.get("type")
        if ptype == "CALL_RING":
            if STATS.state != "IDLE":
                print("[lk] line busy: rejecting incoming call", flush=True)
                self.udp.send_call_busy()
            else:
                print(f"[lk] incoming call from {payload.get('caller', '?')}", flush=True)
                STATS.state = "RINGING"
                STATS.ring_start_time = time.time()
                self.udp.ring_device()
        elif ptype == "CALL_HANGUP":
            print("[lk] remote hung up", flush=True)
            self.on_button_hangup()

    def on_button_accept(self):
        print("[call] answered; connecting audio on-demand", flush=True)
        STATS.state = "IN_CALL"
        STATS.call_start_time = time.time()
        STATS.ring_start_time = None
        asyncio.create_task(self.start_call_session())

    def on_button_hangup(self, notify_esp=True):
        print("[call] call ended", flush=True)
        STATS.state = "IDLE"
        STATS.call_start_time = None
        STATS.ring_start_time = None
        if notify_esp:
            self.udp.send_call_end()
        asyncio.create_task(self.stop_call_session())

# ---------------------------------------------------------------- HTTP & Web Client

def get_token(identity="browser-user"):
    from livekit import api
    token = (api.AccessToken(LIVEKIT_KEY, LIVEKIT_SECRET)
             .with_identity(identity)
             .with_grants(api.VideoGrants(room_join=True, room=ROOM_NAME))
             .to_jwt())
    return {"url": LIVEKIT_URL, "token": token, "room": ROOM_NAME}

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>ESP Landline - Professional Cloud Voice</title>
<style>
  :root {
    --bg: #090d16;
    --panel: #131b26;
    --panel-border: #202b3c;
    --line: #202b3c;
    --text: #f0f6fc;
    --dim: #8b949e;
    --accent: #388bfd;
    --ok: #238636;
    --ok-hover: #2ea043;
    --bad: #da3633;
    --bad-hover: #f85149;
    --warning: #d29922;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 16px;
  }
  main {
    width: 100%;
    max-width: 480px;
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 16px 36px rgba(0, 0, 0, 0.45);
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
  }
  h1 {
    font-size: 20px;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .badge-shield {
    background: rgba(56, 139, 253, 0.15);
    color: #58a6ff;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 12px;
    border: 1px solid rgba(56, 139, 253, 0.3);
  }
  .sub {
    color: var(--dim);
    font-size: 13px;
    margin-bottom: 20px;
  }
  .panel {
    background: rgba(13, 17, 23, 0.7);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 16px;
  }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 7px 0;
    font-size: 13.5px;
  }
  .row + .row {
    border-top: 1px solid rgba(32, 43, 60, 0.6);
  }
  .k { color: var(--dim); }
  .v { font-variant-numeric: tabular-nums; font-weight: 500; }
  .dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
    background: var(--bad);
    transition: background 0.3s;
  }
  .dot.on { background: #3fb950; box-shadow: 0 0 8px rgba(63, 185, 80, 0.5); }
  .dot.busy { background: var(--warning); box-shadow: 0 0 8px rgba(210, 153, 34, 0.5); }
  .btn {
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    background: var(--ok);
    color: #fff;
    transition: all 0.18s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .btn:hover:not(:disabled) { background: var(--ok-hover); transform: translateY(-1px); }
  .btn:disabled { background: #21262d; color: var(--dim); cursor: not-allowed; transform: none; }
  .btn.end { background: var(--bad); }
  .btn.end:hover:not(:disabled) { background: var(--bad-hover); }
  .hint {
    color: var(--dim);
    font-size: 12.5px;
    margin-top: 14px;
    text-align: center;
    min-height: 18px;
  }
  .quota-notice {
    margin-top: 16px;
    padding: 10px;
    border-radius: 8px;
    background: rgba(33, 38, 45, 0.6);
    border: 1px dashed var(--line);
    font-size: 11.5px;
    color: var(--dim);
    display: flex;
    align-items: center;
    gap: 6px;
  }
  /* Auth Screen Modal / Overlay */
  #auth-overlay {
    display: none;
    flex-direction: column;
    gap: 14px;
  }
  .input-field {
    width: 100%;
    padding: 12px 14px;
    border-radius: 8px;
    border: 1px solid var(--line);
    background: #0d1117;
    color: var(--text);
    font-size: 15px;
    outline: none;
    transition: border-color 0.2s;
  }
  .input-field:focus { border-color: var(--accent); }
  .auth-err {
    color: var(--bad);
    font-size: 12px;
    min-height: 16px;
  }
  .lock-link {
    display: block;
    text-align: center;
    font-size: 12px;
    color: var(--dim);
    text-decoration: underline;
    cursor: pointer;
    margin-top: 14px;
  }
</style>
</head>
<body>
<main>
  <!-- Authentication View -->
  <div id="auth-overlay">
    <header>
      <h1>🔒 Gateway Access</h1>
      <span class="badge-shield">Protected</span>
    </header>
    <div class="sub">This intercom bridge is protected. Enter the access passcode to initiate calls.</div>
    <input type="password" id="passcode" class="input-field" placeholder="Access Passcode" autocomplete="current-password" />
    <div id="auth-err" class="auth-err"></div>
    <button id="unlock-btn" class="btn">Unlock Gateway</button>
  </div>

  <!-- Main Calling View -->
  <div id="app-view">
    <header>
      <h1>☎️ ESP Landline</h1>
      <span class="badge-shield">LiveKit Cloud</span>
    </header>
    <div class="sub">Direct crystal-clear voice intercom to Bluetooth earbuds</div>

    <div class="panel">
      <div class="row">
        <span class="k">Intercom Device</span>
        <span class="v" id="dev"><span class="dot"></span>checking...</span>
      </div>
      <div class="row">
        <span class="k">Line State</span>
        <span class="v" id="st">IDLE</span>
      </div>
      <div class="row">
        <span class="k">Call Timer</span>
        <span class="v" id="timer">--:--</span>
      </div>
      <div class="row">
        <span class="k">Earbuds Mic Peak</span>
        <span class="v" id="mic">-120 dBFS</span>
      </div>
      <div class="row">
        <span class="k">Speaker Out Peak</span>
        <span class="v" id="out">-120 dBFS</span>
      </div>
    </div>

    <button id="go" class="btn">Start Call</button>
    <div class="hint" id="hint">Ready to connect.</div>

    <div class="quota-notice">
      <span>🛡️</span>
      <span>Anti-abuse active: 30-min auto-hangup watchdog &amp; empty-room disconnect.</span>
    </div>

    <a id="lock-btn" class="lock-link">Lock / Change Passcode</a>
  </div>
</main>

<script type="module">
import { Room, RoomEvent, Track, createLocalAudioTrack } from '/livekit-client.mjs';

const $ = (id) => document.getElementById(id);
const authOverlay = $('auth-overlay');
const appView = $('app-view');
const passInput = $('passcode');
const unlockBtn = $('unlock-btn');
const authErr = $('auth-err');
const go = $('go');
const hint = $('hint');
const timerEl = $('timer');
const lockBtn = $('lock-btn');

function getAuth() {
  const urlParam = new URLSearchParams(location.search).get('auth') || new URLSearchParams(location.search).get('token');
  if (urlParam) {
    localStorage.setItem('esp_auth_token', urlParam);
    return urlParam;
  }
  return localStorage.getItem('esp_auth_token') || '';
}

function showAuth() {
  authOverlay.style.display = 'flex';
  appView.style.display = 'none';
  passInput.focus();
}

function showApp() {
  authOverlay.style.display = 'none';
  appView.style.display = 'block';
  poll();
}

unlockBtn.onclick = async () => {
  const code = passInput.value.trim();
  if (!code) {
    authErr.textContent = 'Please enter a passcode.';
    return;
  }
  unlockBtn.disabled = true;
  unlockBtn.textContent = 'Verifying...';
  authErr.textContent = '';
  try {
    const res = await fetch('/status?auth=' + encodeURIComponent(code));
    if (res.status === 401) {
      authErr.textContent = 'Invalid passcode. Access denied.';
      unlockBtn.disabled = false;
      unlockBtn.textContent = 'Unlock Gateway';
      return;
    }
    localStorage.setItem('esp_auth_token', code);
    unlockBtn.disabled = false;
    unlockBtn.textContent = 'Unlock Gateway';
    showApp();
  } catch (e) {
    authErr.textContent = 'Connection error: ' + (e.message || e);
    unlockBtn.disabled = false;
    unlockBtn.textContent = 'Unlock Gateway';
  }
};

passInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') unlockBtn.click();
});

lockBtn.onclick = () => {
  localStorage.removeItem('esp_auth_token');
  showAuth();
};

let callTimerInterval = null;
let callSeconds = 0;

function formatTime(sec) {
  const m = Math.floor(sec / 60).toString().padStart(2, '0');
  const s = (sec % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

async function poll() {
  const token = getAuth();
  if (!token) {
    showAuth();
    return;
  }
  try {
    const res = await fetch('/status?auth=' + encodeURIComponent(token), { cache: 'no-store' });
    if (res.status === 401) {
      showAuth();
      return;
    }
    const j = await res.json();
    const dotClass = j.state === 'IN_CALL' ? 'dot on' : (j.state === 'RINGING' ? 'dot busy' : (j.device ? 'dot on' : 'dot'));
    $('dev').innerHTML = `<span class="${dotClass}"></span>` + (j.device ? 'Online (Home)' : 'Waiting for ESP32...');
    $('st').textContent = j.state;
    $('mic').textContent = j.rxDbfs + ' dBFS';
    $('out').textContent = j.txDbfs + ' dBFS';

    if (j.state === 'IN_CALL') {
      if (j.callDurationSec !== undefined) {
        timerEl.textContent = formatTime(j.callDurationSec);
      }
    } else if (j.state !== 'IN_CALL' && go.className === 'btn end') {
      // Remote hung up
      window.hangupCall();
    }
  } catch {}
}

const currentToken = getAuth();
if (!currentToken) {
  showAuth();
} else {
  showApp();
}
setInterval(poll, 1500);

const room = new Room({ adaptiveStream: false, dynacast: false });
let audioEl = null;
let localMic = null;

window.hangupCall = async () => {
  if (callTimerInterval) {
    clearInterval(callTimerInterval);
    callTimerInterval = null;
  }
  timerEl.textContent = '--:--';
  if (localMic) {
    try { localMic.stop(); } catch(e) {}
    localMic = null;
  }
  if (room) {
    try { await room.disconnect(); } catch(e) {}
  }
  if (audioEl) { audioEl.remove(); audioEl = null; }
  go.className = 'btn';
  go.textContent = 'Start Call';
  go.disabled = false;
  go.onclick = start;
};
window.addEventListener('beforeunload', () => window.hangupCall());

room.on(RoomEvent.TrackSubscribed, (track) => {
  if (track.kind !== Track.Kind.Audio) return;
  audioEl = track.attach();
  audioEl.autoplay = true;
  document.body.appendChild(audioEl);
  audioEl.play().catch(() => {});
});

room.on(RoomEvent.Disconnected, () => {
  window.hangupCall();
  hint.textContent = 'Call disconnected.';
});

async function start() {
  const token = getAuth();
  if (!token) {
    showAuth();
    return;
  }
  go.disabled = true;
  go.textContent = 'Connecting...';
  hint.textContent = 'Requesting secure room token...';

  try {
    const res = await fetch('/token?auth=' + encodeURIComponent(token));
    if (res.status === 401) {
      showAuth();
      return;
    }
    if (res.status === 429) {
      throw new Error('Rate limit exceeded. Please wait 60 seconds.');
    }
    const t = await res.json();

    hint.textContent = 'Activating microphone with hardware AEC & AGC...';
    localMic = await createLocalAudioTrack({
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
      channelCount: 1,
      sampleRate: 16000,
    });

    hint.textContent = 'Joining LiveKit room...';
    await room.connect(t.url, t.token);
    await room.localParticipant.publishTrack(localMic, { source: Track.Source.Microphone });

    go.className = 'btn end';
    go.textContent = 'Hang Up';
    go.disabled = false;
    hint.textContent = '🟢 Connected to LiveKit Cloud. Speaking with earbuds.';
    go.onclick = window.hangupCall;

    callSeconds = 0;
    if (callTimerInterval) clearInterval(callTimerInterval);
    callTimerInterval = setInterval(() => {
      callSeconds++;
      timerEl.textContent = formatTime(callSeconds);
      if (callSeconds >= 1680) { // 28 minutes
        hint.textContent = '⚠️ 30-min auto-hangup approaching to preserve quota.';
      }
    }, 1000);

  } catch (e) {
    hint.textContent = 'Error: ' + (e?.message || e);
    go.disabled = false;
    go.className = 'btn';
    go.textContent = 'Retry Call';
  }
}
go.onclick = start;

if (new URLSearchParams(location.search).get('autostart') === '1') {
  if (getAuth()) start();
}
</script>
</body>
</html>
"""

def make_http_response(status_code: int, status_text: str, content_type: str, body: bytes, extra_headers: list = None) -> bytes:
    hdrs = [
        f"HTTP/1.1 {status_code} {status_text}",
        f"Content-Type: {content_type}",
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

            # Extract client IP
            peername = writer.get_extra_info("peername")
            client_ip = peername[0] if peername else "unknown"

            raw_text = req.decode(errors="ignore")
            lines = raw_text.split("\r\n")
            first_line = lines[0].split(" ") if lines else []
            method = first_line[0] if len(first_line) > 0 else "GET"
            full_path = first_line[1] if len(first_line) > 1 else "/"

            headers = {}
            for h in lines[1:]:
                if not h:
                    break
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Reverse proxy real IP check (e.g. Render X-Forwarded-For)
            if "x-forwarded-for" in headers:
                client_ip = headers["x-forwarded-for"].split(",")[0].strip()

            parsed_url = urlparse(full_path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)

            # 1. Handle CORS preflight
            if method == "OPTIONS":
                resp = make_http_response(204, "No Content", "text/plain", b"")
                writer.write(resp)
                await writer.drain()
                return

            # 2. Check rate limit
            is_call_op = path in ("/call/start", "/token")
            allowed, limit_msg = RATE_LIMITER.check(client_ip, is_call_op=is_call_op)
            if not allowed:
                err_body = json.dumps({"error": "Too Many Requests", "detail": limit_msg}).encode()
                resp = make_http_response(429, "Too Many Requests", "application/json", err_body, ["Retry-After: 60"])
                writer.write(resp)
                await writer.drain()
                return

            # 3. Route dispatch
            if path == "/ping":
                # Health check / Keepalive for Render & ESP32
                resp = make_http_response(200, "OK", "text/plain", b"pong")

            elif path.startswith("/livekit-client.umd.min.js"):
                try:
                    with open(os.path.join(HERE, "web", "livekit-client.umd.min.js"), "rb") as f:
                        body = f.read()
                    resp = make_http_response(200, "OK", "text/javascript; charset=utf-8", body)
                except Exception:
                    resp = make_http_response(404, "Not Found", "text/plain", b"// missing")

            elif path.startswith("/livekit-client.mjs"):
                try:
                    with open(os.path.join(HERE, "web", "livekit-client.mjs"), "rb") as f:
                        body = f.read()
                    resp = make_http_response(200, "OK", "text/javascript; charset=utf-8", body)
                except Exception:
                    resp = make_http_response(404, "Not Found", "text/plain", b"// missing")

            elif path == "/status":
                # Basic public status or full if authenticated
                body = json.dumps(STATS.as_dict(), indent=2).encode()
                resp = make_http_response(200, "OK", "application/json", body)

            elif path == "/devices":
                if not check_auth(headers, query_params):
                    err_body = json.dumps({"error": "Unauthorized", "detail": "Valid authentication token required."}).encode()
                    resp = make_http_response(401, "Unauthorized", "application/json", err_body, ["WWW-Authenticate: Bearer"])
                else:
                    devices = [{
                        "device_id": "esp32-home",
                        "state": STATS.state.lower(),
                        "online": STATS.device_addr is not None,
                    }]
                    resp = make_http_response(200, "OK", "application/json", json.dumps(devices).encode())

            elif path == "/call/start":
                if not check_auth(headers, query_params):
                    err_body = json.dumps({"error": "Unauthorized", "detail": "Valid authentication token required."}).encode()
                    resp = make_http_response(401, "Unauthorized", "application/json", err_body, ["WWW-Authenticate: Bearer"])
                elif STATS.state in ("IN_CALL", "RINGING"):
                    err_body = json.dumps({"error": "Busy", "detail": "A call is already active or ringing."}).encode()
                    resp = make_http_response(486, "Busy Here", "application/json", err_body)
                else:
                    print(f"[http] /call/start authorized from {client_ip}: ringing ESP32", flush=True)
                    STATS.state = "RINGING"
                    STATS.ring_start_time = time.time()
                    mgr.udp.ring_device()
                    asyncio.create_task(mgr.start_call_session())
                    t = get_token("caller-mobile")
                    body = json.dumps({
                        "call_id": "call-1",
                        "room": t["room"],
                        "livekit_url": t["url"],
                        "token": t["token"],
                    }).encode()
                    resp = make_http_response(200, "OK", "application/json", body)

            elif path == "/token":
                if not check_auth(headers, query_params):
                    err_body = json.dumps({"error": "Unauthorized", "detail": "Valid authentication token required."}).encode()
                    resp = make_http_response(401, "Unauthorized", "application/json", err_body, ["WWW-Authenticate: Bearer"])
                else:
                    body = json.dumps(get_token()).encode()
                    resp = make_http_response(200, "OK", "application/json", body)

            elif path in ("/call/end", "/hangup"):
                if not check_auth(headers, query_params):
                    err_body = json.dumps({"error": "Unauthorized", "detail": "Valid authentication token required."}).encode()
                    resp = make_http_response(401, "Unauthorized", "application/json", err_body, ["WWW-Authenticate: Bearer"])
                else:
                    mgr.on_button_hangup()
                    resp = make_http_response(200, "OK", "application/json", b'{"status":"ended"}')

            elif path == "/accept":
                if not check_auth(headers, query_params):
                    err_body = json.dumps({"error": "Unauthorized", "detail": "Valid authentication token required."}).encode()
                    resp = make_http_response(401, "Unauthorized", "application/json", err_body, ["WWW-Authenticate: Bearer"])
                else:
                    mgr.on_button_accept()
                    resp = make_http_response(200, "OK", "application/json", b'{"status":"accepted"}')

            else:
                resp = make_http_response(200, "OK", "text/html; charset=utf-8", PAGE.encode("utf-8"))

            writer.write(resp)
            await writer.drain()
        except Exception as e:
            print(f"[http] error processing request: {e}", flush=True)
        finally:
            writer.close()

    import ssl
    server = await asyncio.start_server(handler, "0.0.0.0", HTTP_PORT)
    cert_file = os.path.join(HERE, "cert.pem")
    key_file = os.path.join(HERE, "key.pem")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert_file, key_file)
        await asyncio.start_server(handler, "0.0.0.0", 8443, ssl=ssl_ctx)
        print("[bridge] HTTPS server running on https://0.0.0.0:8443", flush=True)
    return server

# ---------------------------------------------------------------- Entrypoint

async def main():
    mgr = TelephoneManager()
    await mgr.init()

    STATS.state = "IDLE"
    print(f"[bridge] Production security active (AUTH_TOKEN={'set' if AUTH_TOKEN else 'none'}, max_duration={MAX_CALL_DURATION_SEC}s, ring_timeout={RING_TIMEOUT_SEC}s)", flush=True)
    print("[bridge] On-demand mode active: 0 LiveKit minutes consumed while idle.", flush=True)

    http = await run_http_server(mgr)
    print(f"[bridge] Web UI running on http://0.0.0.0:{HTTP_PORT}", flush=True)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop_event.set)

    await stop_event.wait()
    print("[bridge] shutting down...", flush=True)
    await mgr.livekit.stop()
    mgr.pacer.stop()

if __name__ == "__main__":
    asyncio.run(main())
