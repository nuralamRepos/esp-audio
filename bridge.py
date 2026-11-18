#!/usr/bin/env python3
"""
esp-telephone audio bridge.
Connects ESP32 HFP AG (UDP PCM16 16kHz) <-> LiveKit Cloud Room.

Features:
  - Downlink audio filtering: anti-alias bandpass (300Hz-3400Hz), smooth AGC, soft limiter.
  - Paced 20ms datagram sender (eliminates network burst jitter to ESP32).
  - Physical call control: handles ring signal, button press to accept, hangup.
  - Native LiveKit Cloud data packet messaging (serverless signaling).
  - Built-in web client on port 8080 for immediate browser calling from anywhere.
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

# Protocol Opcodes
PKT_CONTROL     = 0x01
PKT_AUDIO       = 0x02
PKT_PING        = 0x03
PKT_PONG        = 0x04
PKT_CALL_RING   = 0x10
PKT_CALL_ACCEPT = 0x11
PKT_CALL_END    = 0x12
PKT_CALL_BUSY   = 0x13

# ---------------------------------------------------------------- Audio Filter & AGC

class AudioProcessor:
    """Bandpass filter (300-3400 Hz) + smooth AGC + soft limiter."""
    def __init__(self, sample_rate=16000):
        self.sr = sample_rate
        self._init_filters()
        self.gain = 1.0
        self.target_peak = 18000.0  # target peak around -5 dBFS

    def _init_filters(self):
        # Direct Form II transposed coefficients for 16kHz
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
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.rx_frames = 0
        self.tx_frames = 0
        self.dropped_frames = 0
        self.rx_dbfs = -120.0
        self.tx_dbfs = -120.0
        self.start_time = time.time()

    def as_dict(self):
        return {
            "device": self.device_addr is not None,
            "deviceAddr": list(self.device_addr) if self.device_addr else None,
            "state": self.state,
            "activeCallId": self.active_call_id,
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
    def __init__(self, udp_link: UdpLinkProtocol, pacer: DownlinkPacer, on_data_packet=None):
        self.udp_link = udp_link
        self.pacer = pacer
        self.on_data_packet = on_data_packet
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

        self.livekit = LiveKitSession(self.udp, self.pacer, on_data_packet=self.on_livekit_data)

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
                self.udp.ring_device()
        elif ptype == "CALL_HANGUP":
            print("[lk] remote hung up", flush=True)
            self.on_button_hangup()

    def on_button_accept(self):
        print("[call] answered; connecting audio on-demand", flush=True)
        STATS.state = "IN_CALL"
        asyncio.create_task(self.start_call_session())

    def on_button_hangup(self, notify_esp=True):
        print("[call] call ended", flush=True)
        STATS.state = "IDLE"
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
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1">
<title>ESP Telephone - Cloud Calling</title>
<style>
  :root{
    --bg:#0e1116; --panel:#161b22; --line:#2a313c; --ink:#e6edf3;
    --dim:#8b949e; --accent:#4a9eff; --ok:#3fb950; --bad:#f85149;
  }
  *{box-sizing:border-box}
  body{background:var(--bg);color:var(--ink);margin:0;
       font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;
       display:grid;place-items:center;min-height:100vh;padding:16px}
  main{width:min(560px,100%)}
  h1{font-size:22px;margin:0 0 2px;font-weight:650}
  .sub{color:var(--dim);font-size:13px;margin-bottom:20px}
  .panel{background:var(--panel);border:1px solid var(--line);
         border-radius:12px;padding:16px;margin-bottom:12px}
  .row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;font-size:14px}
  .row+.row{border-top:1px solid rgba(42,49,60,.55)}
  .k{color:var(--dim)}
  .v{font-variant-numeric:tabular-nums}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;background:var(--bad)}
  .dot.on{background:var(--ok)}
  button{width:100%;padding:14px;border:0;border-radius:9px;font-size:16px;
         font-weight:600;cursor:pointer;background:var(--ok);color:#fff;transition:background .15s}
  button:hover:not(:disabled){filter:brightness(1.1)}
  button:disabled{background:#2a313c;color:var(--dim);cursor:default}
  button.end{background:var(--bad)}
  .hint{color:var(--dim);font-size:12px;margin-top:12px;text-align:center}
</style>
<main>
  <h1>☎️ ESP Telephone</h1>
  <div class=sub>Direct calling to home landline via LiveKit Cloud</div>

  <div class=panel>
    <div class=row><span class=k>Landline Device</span>
      <span class=v id=dev><span class="dot"></span>checking...</span></div>
    <div class=row><span class=k>Call State</span>
      <span class=v id=st>IDLE</span></div>
    <div class=row><span class=k>Earbuds Mic</span>
      <span class=v id=mic>-120 dBFS</span></div>
    <div class=row><span class=k>Speaker Out</span>
      <span class=v id=out>-120 dBFS</span></div>
  </div>

  <button id=go>Start Call</button>
  <div class=hint id=hint>Ready to connect.</div>
</main>

<script type=module>
import { Room, RoomEvent, Track, createLocalAudioTrack } from '/livekit-client.mjs';

const $ = (id) => document.getElementById(id);
const go = $('go'), hint = $('hint');

async function poll() {
  try {
    const j = await (await fetch('/status', { cache: 'no-store' })).json();
    $('dev').innerHTML = `<span class="dot${j.device ? ' on' : ''}"></span>` + (j.device ? 'online' : 'offline');
    $('st').textContent = j.state;
    $('mic').textContent = j.rxDbfs + ' dBFS';
    $('out').textContent = j.txDbfs + ' dBFS';
  } catch {}
}
poll(); setInterval(poll, 1000);

const room = new Room({ adaptiveStream: false, dynacast: false });
let audioEl = null;
let localMic = null;

window.hangupCall = async () => {
  if (localMic) {
    try { localMic.stop(); } catch(e) {}
    localMic = null;
  }
  if (room) {
    try { await room.disconnect(); } catch(e) {}
  }
  if (audioEl) { audioEl.remove(); audioEl = null; }
  go.className = ''; go.textContent = 'Start Call'; go.onclick = start;
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
  go.disabled = true; go.textContent = 'Connecting...';
  try {
    const res = await fetch('/token');
    const t = await res.json();
    localMic = await createLocalAudioTrack({
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    });
    await room.connect(t.url, t.token);
    await room.localParticipant.publishTrack(localMic, { source: Track.Source.Microphone });

    go.className = 'end';
    go.textContent = 'Hang Up';
    go.disabled = false;
    hint.textContent = 'Connected to LiveKit Cloud. Speaking with earbuds.';
    go.onclick = window.hangupCall;
  } catch (e) {
    hint.textContent = 'Error: ' + (e?.message || e);
    go.disabled = false; go.textContent = 'Retry';
  }
}
go.onclick = start;
if (new URLSearchParams(location.search).get('autostart') === '1') {
  start();
}
</script>
"""

async def run_http_server(mgr: TelephoneManager):
    async def handler(reader, writer):
        try:
            req = await reader.read(2048)
            if not req:
                return
            line = req.split(b"\r\n", 1)[0].decode(errors="ignore")
            path = line.split(" ")[1] if " " in line else "/"

            if path.startswith("/livekit-client.umd.min.js"):
                try:
                    with open(os.path.join(HERE, "web", "livekit-client.umd.min.js"), "rb") as f:
                        body = f.read()
                    ctype = "text/javascript; charset=utf-8"
                except Exception:
                    body = b"// missing"
                    ctype = "text/javascript"
            elif path.startswith("/livekit-client.mjs"):
                try:
                    with open(os.path.join(HERE, "web", "livekit-client.mjs"), "rb") as f:
                        body = f.read()
                    ctype = "text/javascript; charset=utf-8"
                except Exception:
                    body = b"// missing"
                    ctype = "text/javascript"
            elif path.startswith("/status"):
                body = json.dumps(STATS.as_dict(), indent=2).encode()
                ctype = "application/json"
            elif path.startswith("/devices"):
                devices = [{
                    "device_id": "esp32-home",
                    "state": STATS.state.lower(),
                    "online": STATS.device_addr is not None,
                }]
                body = json.dumps(devices).encode()
                ctype = "application/json"
            elif path.startswith("/call/start"):
                if STATS.state == "IN_CALL":
                    writer.write(b"HTTP/1.1 486 Busy Here\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return
                print("[http] /call/start requested: sending PKT_CALL_RING to ESP32", flush=True)
                STATS.state = "RINGING"
                mgr.udp.ring_device()
                asyncio.create_task(mgr.start_call_session())
                t = get_token("caller-mobile")
                body = json.dumps({
                    "call_id": "call-1",
                    "room": t["room"],
                    "livekit_url": t["url"],
                    "token": t["token"],
                }).encode()
                ctype = "application/json"
            elif path.startswith("/ping"):
                body = b"pong"
                ctype = "text/plain"
            elif path.startswith("/call/end"):
                mgr.on_button_hangup()
                STATS.state = "IDLE"
                body = b'{"status":"ended"}'
                ctype = "application/json"
            elif path.startswith("/token"):
                body = json.dumps(get_token()).encode()
                ctype = "application/json"
            elif path.startswith("/accept"):
                mgr.on_button_accept()
                body = b'{"status":"accepted"}'
                ctype = "application/json"
            elif path.startswith("/hangup"):
                mgr.on_button_hangup()
                body = b'{"status":"hungup"}'
                ctype = "application/json"
            else:
                body = PAGE.encode()
                ctype = "text/html; charset=utf-8"

            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Type: {ctype}\r\n".encode()
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Access-Control-Allow-Origin: *\r\n"
                + b"Access-Control-Allow-Headers: *\r\n"
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        except Exception:
            pass
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
