#!/usr/bin/env python3
"""
esp-telephone audio bridge & backend (Production aiohttp WebSocket & REST).
Connects Multiple Android App Callers -> Single ESP32 Hardware Listener.

Architecture:
  - Android Applications: UI, native audio hardware (AEC/NS/AGC), call controls.
  - Custom Backend: Authentication, atomic call locking (single-active-call policy), token issuance.
  - LiveKit Cloud: Real-time WebRTC media conference.
  - Media Gateway: Bridges ESP32 WebSocket / UDP audio <-> LiveKit room audio.
  - ESP32: Lightweight audio hardware (16kHz mSBC) + physical button.
"""

import asyncio
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque
import hmac
import numpy as np
import aiohttp
from aiohttp import web

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

LIVEKIT_URL = os.environ.get("LIVEKIT_URL", "wss://esp-audio-telephone-6w0f0mw5.livekit.cloud")
LIVEKIT_KEY = os.environ.get("LIVEKIT_API_KEY", os.environ.get("LIVEKIT_KEY", "API7RGzY8gPJzUh"))
LIVEKIT_SECRET = os.environ.get("LIVEKIT_API_SECRET", os.environ.get("LIVEKIT_SECRET", "39eygVhnkYtXPhW93JZKPVufdN6ozvBLGzCXwSenrjOA"))
ROOM_NAME = os.environ.get("LIVEKIT_ROOM", "landline")

AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "nuralam9922").strip()
INACTIVITY_TIMEOUT_SEC = int(os.environ.get("INACTIVITY_TIMEOUT_SEC", 900))  # 15m dead-air silence timeout
RING_TIMEOUT_SEC = int(os.environ.get("RING_TIMEOUT_SEC", 45))  # 45s ringing timeout
# How long a call survives the device link dropping. A reconnect under load is
# normal; hanging up on it made every blip look like the caller left.
DEVICE_OFFLINE_GRACE_SEC = int(os.environ.get("DEVICE_OFFLINE_GRACE_SEC", 25))
MAX_CALLS_PER_MIN = int(os.environ.get("MAX_CALLS_PER_MIN", 30))
MAX_REQ_PER_MIN = int(os.environ.get("MAX_REQ_PER_MIN", 120))

CLIENT_WEBSOCKETS = set()

def notify_status_change():
    """Schedules a status broadcast to all connected Android WebSocket clients."""
    if CLIENT_WEBSOCKETS:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(broadcast_status())
        except RuntimeError:
            pass

async def broadcast_status():
    if not CLIENT_WEBSOCKETS:
        return
    payload = STATS.as_dict()
    dead = []
    for ws in list(CLIENT_WEBSOCKETS):
        try:
            if not ws.closed:
                await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        CLIENT_WEBSOCKETS.discard(ws)

def notify_extensions_change(device_link=None):
    if CLIENT_WEBSOCKETS:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(broadcast_extensions())
        except RuntimeError:
            pass
    if device_link:
        device_link.send_extension_list()

async def broadcast_extensions():
    if not CLIENT_WEBSOCKETS:
        return
    payload = {
        "type": "extensions_update",
        "extensions": EXTENSIONS.list_extensions()
    }
    dead = []
    for ws in list(CLIENT_WEBSOCKETS):
        try:
            if not ws.closed:
                await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        CLIENT_WEBSOCKETS.discard(ws)

# Protocol Opcodes (ESP32 <-> Gateway)
PKT_CONTROL     = 0x01
PKT_AUDIO       = 0x02
PKT_PING        = 0x03
PKT_PONG        = 0x04
PKT_CALL_RING   = 0x10
PKT_CALL_ACCEPT = 0x11
PKT_CALL_END    = 0x12
PKT_CALL_BUSY   = 0x13
PKT_EXT_LIST    = 0x14
PKT_CALL_DIAL   = 0x15
PKT_HEALTH      = 0x16

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

    def clear(self):
        self.general_limits.clear()
        self.call_limits.clear()

RATE_LIMITER = RateLimiter()

def check_auth(request: web.Request) -> bool:
    """Verifies that the request comes from an authorized Android application or ESP32."""
    if not AUTH_TOKEN:
        return True
    token = request.headers.get("x-auth-token")
    if not token:
        auth_hdr = request.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
        elif auth_hdr:
            token = auth_hdr.strip()
    if not token:
        token = request.query.get("auth", "") or request.query.get("token", "")

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
        # 18000 was 55% of full scale (-5.2 dBFS), so even a perfectly healthy
        # call arrived at the earbuds already 5 dB down. Combined with the
        # bandpass loss and the earbud's own ceiling that is the "sound is low"
        # symptom. 28000 is 85% (-1.4 dBFS): as loud as the link can carry
        # without the soft limiter working on every peak.
        #
        # This is the only remaining gain stage. The ESP32 already runs the HFP
        # speaker volume at 15/15, which is the protocol maximum, and the PCM is
        # passed through untouched between here and SCO.
        self.target_peak = 28000.0

    def _init_filters(self):
        self.hp_b = np.array([0.92006, -1.84013, 0.92006], dtype=np.float32)
        self.hp_a = np.array([1.0, -1.83373, 0.84653], dtype=np.float32)
        self.hp_z = np.zeros(2, dtype=np.float32)

        self.lp_b = np.array([0.24524, 0.49048, 0.24524], dtype=np.float32)
        self.lp_a = np.array([1.0, -0.40795, 0.38890], dtype=np.float32)
        self.lp_z = np.zeros(2, dtype=np.float32)

    def process_pcm16(self, pcm_bytes: bytes) -> bytes:
        if not pcm_bytes:
            return b""
        samples = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32)

        y_hp = np.empty_like(samples)
        for i, x in enumerate(samples):
            y = self.hp_b[0] * x + self.hp_z[0]
            self.hp_z[0] = self.hp_b[1] * x - self.hp_a[1] * y + self.hp_z[1]
            self.hp_z[1] = self.hp_b[2] * x - self.hp_a[2] * y
            y_hp[i] = y

        y_lp = np.empty_like(y_hp)
        for i, x in enumerate(y_hp):
            y = self.lp_b[0] * x + self.lp_z[0]
            self.lp_z[0] = self.lp_b[1] * x - self.lp_a[1] * y + self.lp_z[1]
            self.lp_z[1] = self.lp_b[2] * x - self.lp_a[2] * y
            y_lp[i] = y

        cur_peak = float(np.max(np.abs(y_lp))) if len(y_lp) > 0 else 0.0
        if cur_peak > 100.0:
            target_g = self.target_peak / cur_peak
            if target_g < self.gain:
                self.gain = 0.8 * self.gain + 0.2 * target_g
            else:
                self.gain = 0.995 * self.gain + 0.005 * target_g
            self.gain = max(0.2, min(self.gain, 6.0))

        out = y_lp * self.gain

        limit = 32000.0
        mask = np.abs(out) > limit
        if np.any(mask):
            out[mask] = np.sign(out[mask]) * (limit + (32760.0 - limit) * np.tanh((np.abs(out[mask]) - limit) / (32760.0 - limit)))

        out = np.clip(out, -32767.0, 32767.0).astype(np.int16)
        return out.tobytes()

# ---------------------------------------------------------------- Backend Call State & Telemetry

class DeviceCallLock:
    """Enforces atomic single-active-call policy with queueing, hold & reject."""
    def __init__(self):
        self.device_id = DEVICE_ID
        self.device_addr = None
        self.state = "IDLE"  # IDLE, RINGING, IN_CALL, ON_HOLD
        self.is_on_hold = False
        self.active_call_id = None
        self.active_caller_id = None
        self.caller_id = None
        self.target_ext = None
        self.call_direction = None # "to_esp" or "from_esp"
        self.call_start_time = None
        self.ring_start_time = None
        self.last_activity_time = time.time()
        self.call_queue = []  # list of {"call_id": ..., "caller_id": ..., "queued_at": ..., "token_data": ...}
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.rx_frames = 0
        self.tx_frames = 0
        self.dropped_frames = 0
        self.rx_dbfs = -120.0
        self.tx_dbfs = -120.0
        self.start_time = time.time()
        # Reported by the device itself on every connect (PKT_HEALTH).
        # boot_count rising between two reports means the chip RESTARTED; a
        # reconnect with an unchanged count is only a transport blip. This is
        # the difference between "the firmware crashed" and "Wi-Fi hiccuped",
        # and it cannot be told apart from the socket alone.
        self.dev_boot_count = None
        self.dev_brownouts = None
        self.dev_free_heap = None
        self.dev_reset_reason = None
        self.dev_connects = 0

    def as_dict(self):
        call_dur = 0
        if self.state in ("IN_CALL", "ON_HOLD") and self.call_start_time:
            call_dur = int(time.time() - self.call_start_time)
        return {
            "device_id": self.device_id,
            "device_name": "হোম ল্যান্ডলাইন",
            "online": self.device_addr is not None,
            "state": self.state.lower(),
            "availability": "available" if self.state == "IDLE" else "busy",
            "on_hold": self.is_on_hold,
            "active_call_id": self.active_call_id,
            "active_caller_id": self.active_caller_id,
            "caller_id": self.caller_id or self.active_caller_id,
            "target_ext": self.target_ext,
            "call_direction": self.call_direction,
            "call_duration_sec": call_dur,
            "inactivity_timeout_sec": INACTIVITY_TIMEOUT_SEC,
            "queue_len": len(self.call_queue),
            "queued_callers": [q["caller_id"] for q in self.call_queue],
            "rx_dbfs": round(self.rx_dbfs, 1),
            "tx_dbfs": round(self.tx_dbfs, 1),
            "uptime_sec": int(time.time() - self.start_time),
            "device": {
                "boot_count": self.dev_boot_count,
                "brownouts": self.dev_brownouts,
                "free_heap": self.dev_free_heap,
                "reset_reason": self.dev_reset_reason,
                "connects": self.dev_connects,
            },
        }

STATS = DeviceCallLock()

# ---------------------------------------------------------------- state tracing
# ---------------------------------------------------------------- log capture
# The bridge runs on Render, where stdout is only visible in the dashboard. That
# made every runtime failure ("the call closed itself while ringing") invisible
# from the client side. Everything printed is now ALSO kept in a bounded ring
# buffer and served from /logs, so the exact line that ended a call can be read
# over HTTP while it is happening.
import collections as _collections

LOG_RING = _collections.deque(maxlen=1000)
_log_seq = 0


class _TeeStdout:
    def __init__(self, real):
        self._real = real
        self._buf = ""
        self._lock = threading.Lock()

    def write(self, data):
        global _log_seq
        if not data:
            return 0
        try:
            self._real.write(data)
        except Exception:
            pass
        with self._lock:
            self._buf += data
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                _log_seq += 1
                LOG_RING.append((_log_seq, time.strftime("%H:%M:%S"), line))
        return len(data)

    def flush(self):
        try:
            self._real.flush()
        except Exception:
            pass

    def isatty(self):
        return False


sys.stdout = _TeeStdout(sys.stdout)


def set_state(new_state, why=""):
    """Change the bridge call state and ALWAYS log the caller.

    Call state used to change in eight different places with no record of which
    one fired, so a call that "closed itself while ringing" could not be traced.
    Every transition now prints the old -> new value plus the immediate caller,
    which makes the culprit a single log line instead of an investigation.
    """
    old = STATS.state
    if old == new_state:
        return
    STATS.state = new_state
    import inspect
    caller = "?"
    try:
        for fr in inspect.stack()[1:4]:
            if fr.function not in ("set_state", "notify_status_change"):
                caller = f"{fr.function}:{fr.lineno}"
                break
    except Exception:
        pass
    print(f"[state] {old} -> {new_state}  ({caller}) {why}".rstrip(), flush=True)


# ---------------------------------------------------------------- 4-Digit Extension Directory (Zero Collision PBX Registry)

EXTENSIONS_DB_FILE = os.path.join(HERE, "extensions_db.json")

class ExtensionRegistry:
    """Manages unique 4-digit logical phone extensions (1001-9999 for mobile apps/web, 0000 for ESP32).
    Implements a Hotel Check-In pattern to guarantee ZERO collisions, permanent binding to client_id (UUID),
    and persistence across restarts.
    """
    def __init__(self):
        self._entries = {}      # ext -> dict (runtime socket & state)
        self._device_map = {}   # client_id -> {"ext": "1001", "display_name": "..."}
        self._load_db()

    def _load_db(self):
        if os.path.exists(EXTENSIONS_DB_FILE):
            try:
                with open(EXTENSIONS_DB_FILE, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._device_map = data
                        print(f"[registry] Loaded {len(self._device_map)} permanent extension assignments from database", flush=True)
            except Exception as e:
                print(f"[registry] Notice loading extensions db: {e}", flush=True)

    def _save_db(self):
        try:
            with open(EXTENSIONS_DB_FILE, "w") as f:
                json.dump(self._device_map, f, indent=2)
        except Exception as e:
            print(f"[registry] Notice saving extensions db: {e}", flush=True)

    def get_or_assign(self, client_id: str, display_name: str, requested_ext: str = None) -> tuple[str, bool]:
        """Auto-assigns or returns the unique permanent extension for this client_id.
        Guarantees ZERO COLLISIONS.
        """
        client_id = (client_id or "anonymous").strip()
        display_name = (display_name or f"User {client_id[:6]}").strip()

        # 1. Existing client: return their permanently assigned extension
        if client_id in self._device_map:
            assigned = self._device_map[client_id]["ext"]
            self._device_map[client_id]["display_name"] = display_name
            self._save_db()
            return assigned, False

        # 2. Check all currently assigned extensions
        taken_exts = {v["ext"] for v in self._device_map.values()}
        taken_exts.add("0000")  # Reserved for ESP32

        # 3. If client requested an available valid 4-digit extension, grant it
        if requested_ext and len(requested_ext) == 4 and requested_ext.isdigit() and requested_ext != "0000":
            if requested_ext not in taken_exts:
                self._device_map[client_id] = {"ext": requested_ext, "display_name": display_name}
                self._save_db()
                return requested_ext, True

        # 4. Sequentially assign the lowest free 4-digit extension in pool [1001..9999]
        for candidate in range(1001, 10000):
            c_str = f"{candidate:04d}"
            if c_str not in taken_exts:
                self._device_map[client_id] = {"ext": c_str, "display_name": display_name}
                self._save_db()
                return c_str, True

        fallback = f"{np.random.randint(1001, 9999):04d}"
        self._device_map[client_id] = {"ext": fallback, "display_name": display_name}
        self._save_db()
        return fallback, True

    def register(self, ext: str, client_id: str, display_name: str, ws: web.WebSocketResponse = None) -> tuple[bool, str, str]:
        """Registers a live client. Auto-resolves extensions to prevent collision."""
        client_id = (client_id or "").strip()
        if not client_id:
            return False, "client_id is required", ""

        assigned_ext, is_new = self.get_or_assign(client_id, display_name, requested_ext=ext)
        now = time.time()

        self._entries[assigned_ext] = {
            "extension": assigned_ext,
            "client_id": client_id,
            "display_name": display_name or self._device_map.get(client_id, {}).get("display_name", f"User {assigned_ext}"),
            "last_seen": now,
            "ws": ws
        }
        return True, "Registered successfully", assigned_ext

    def heartbeat(self, client_id: str):
        now = time.time()
        for ext, info in self._entries.items():
            if info.get("client_id") == client_id:
                info["last_seen"] = now

    def deregister(self, ext: str, client_id: str) -> bool:
        existing = self._entries.get(ext)
        if existing and existing.get("client_id") == client_id:
            del self._entries[ext]
            return True
        return False

    def get_by_extension(self, ext: str) -> dict | None:
        return self._entries.get(ext)

    def list_extensions(self) -> list[dict]:
        now = time.time()
        result = [
            {
                "extension": "0000",
                "display_name": "ESP32 ল্যান্ডলাইন",
                "client_id": "esp32-home",
                "online": STATS.device_addr is not None,
                "state": STATS.state.lower()
            }
        ]
        # Include all known registered devices from persistent database
        seen_exts = {"0000"}
        for client_id, dev_info in self._device_map.items():
            ext = dev_info["ext"]
            seen_exts.add(ext)
            live = self._entries.get(ext)
            ws = live.get("ws") if live else None
            is_online = (ws is not None and not ws.closed) or (live is not None and (now - live.get("last_seen", 0) < 120))
            result.append({
                "extension": ext,
                "display_name": dev_info.get("display_name", f"User {ext}"),
                "client_id": client_id,
                "online": is_online,
                "state": "idle" if is_online else "offline"
            })

        return sorted(result, key=lambda x: x["extension"])

EXTENSIONS = ExtensionRegistry()

def compute_dbfs(pcm: bytes):
    if not pcm or len(pcm) < 2:
        return -120.0
    arr = np.frombuffer(pcm, dtype=np.int16).astype(np.float32)
    peak = float(np.max(np.abs(arr)))
    if peak <= 1.0:
        return -120.0
    return max(-120.0, 20.0 * np.log10(peak / 32767.0))

# ---------------------------------------------------------------- Dual Device Link (WebSocket & UDP)

class DeviceLink:
    """Unified transport supporting direct WebSocket connection and local UDP."""
    def __init__(self, on_audio_rx, on_call_accept, on_call_end):
        self.on_audio_rx = on_audio_rx
        self.on_call_accept = on_call_accept
        self.on_call_end = on_call_end
        self.ws = None
        self.udp_transport = None
        self.udp_addr = None

    def send_audio(self, pcm: bytes):
        if self.ws and not self.ws.closed:
            try:
                asyncio.create_task(self.ws.send_bytes(bytes([PKT_AUDIO]) + pcm))
                STATS.tx_bytes += len(pcm)
                STATS.tx_frames += 1
                STATS.tx_dbfs = compute_dbfs(pcm)
            except Exception:
                pass
        elif self.udp_transport and self.udp_addr:
            self.udp_transport.sendto(bytes([PKT_AUDIO]) + pcm, self.udp_addr)
            STATS.tx_bytes += len(pcm)
            STATS.tx_frames += 1
            STATS.tx_dbfs = compute_dbfs(pcm)

    def ring_device(self):
        print("[link] ringing ESP32 hardware", flush=True)
        if self.ws and not self.ws.closed:
            try:
                asyncio.create_task(self.ws.send_bytes(bytes([PKT_CALL_RING])))
            except Exception:
                pass
        elif self.udp_transport and self.udp_addr:
            self.udp_transport.sendto(bytes([PKT_CALL_RING]), self.udp_addr)

    def send_call_end(self):
        print("[link] sending call end to ESP32", flush=True)
        if self.ws and not self.ws.closed:
            try:
                asyncio.create_task(self.ws.send_bytes(bytes([PKT_CALL_END])))
            except Exception:
                pass
        elif self.udp_transport and self.udp_addr:
            self.udp_transport.sendto(bytes([PKT_CALL_END]), self.udp_addr)

    def send_call_accept(self):
        """Tell the ESP32 that the far end answered.

        THIS WAS MISSING, AND IT IS WHY A CALL HAD NO SOUND.

        When the caller pressed Answer in the Android app, /call/accept ran
        on_button_accept(), which flipped the bridge to IN_CALL and started
        LiveKit - but the device was never told. The ESP32 therefore stayed in
        OLED_STATE_INCOMING with hfp_call_start_ringing() still owning the audio
        path:

            audio_pipe_set_source(AUDIO_SRC_TONE)      <- ringing tone
            audio_pipe_net_set_active(false)           <- never set true

        and audio_pipe_net_play() begins with

            if (!s_net_active) return;

        so every 20 ms PCM frame the bridge sent was dropped at the door. The
        capture shows PKT_CALL_RING arriving and then no "call req: remote party
        answered call" line at all, which is the fingerprint of a missing accept.
        The earbuds rang, then went silent, while the phone sat in a call that
        carried nothing.

        The ESP32-initiated path already works: it sends PKT_CALL_ACCEPT itself
        and the bridge answers with on_button_accept(notify_esp=False) so the two
        do not echo each other.
        """
        print("[link] sending call accept to ESP32", flush=True)
        if self.ws and not self.ws.closed:
            try:
                asyncio.create_task(self.ws.send_bytes(bytes([PKT_CALL_ACCEPT])))
            except Exception:
                pass
        elif self.udp_transport and self.udp_addr:
            self.udp_transport.sendto(bytes([PKT_CALL_ACCEPT]), self.udp_addr)

    def send_call_busy(self):
        if self.ws and not self.ws.closed:
            try:
                asyncio.create_task(self.ws.send_bytes(bytes([PKT_CALL_BUSY])))
            except Exception:
                pass
        elif self.udp_transport and self.udp_addr:
            self.udp_transport.sendto(bytes([PKT_CALL_BUSY]), self.udp_addr)

    def send_extension_list(self):
        if not self.ws or self.ws.closed:
            return
        active_exts = [e["extension"] for e in EXTENSIONS.list_extensions() if e["extension"] != "0000" and e["online"]]
        pkt = bytearray([PKT_EXT_LIST, min(len(active_exts), 16)])
        for e in active_exts[:16]:
            pkt.extend(e.encode("ascii")[:4])
        try:
            asyncio.create_task(self.ws.send_bytes(bytes(pkt)))
        except Exception:
            pass

# ---------------------------------------------------------------- UDP Link Protocol (Fallback)

class UdpLinkProtocol(asyncio.DatagramProtocol):
    def __init__(self, device_link: DeviceLink):
        self.device_link = device_link

    def connection_made(self, transport):
        self.device_link.udp_transport = transport
        print(f"[udp] listening on port {UDP_PORT}", flush=True)

    def datagram_received(self, data, addr):
        if not data:
            return
        kind = data[0]

        if kind == PKT_CONTROL:
            if self.device_link.udp_addr != addr:
                print(f"[udp] ESP32 hardware discovered at {addr[0]}:{addr[1]}", flush=True)
                self.device_link.udp_addr = addr
                STATS.device_addr = addr
            self.device_link.udp_transport.sendto(bytes([PKT_CONTROL]) + b"HERE", addr)

        elif kind == PKT_PING:
            self.device_link.udp_addr = addr
            STATS.device_addr = addr
            self.device_link.udp_transport.sendto(bytes([PKT_PONG]), addr)

        elif kind == PKT_AUDIO:
            self.device_link.udp_addr = addr
            STATS.device_addr = addr
            pcm = data[1:]
            STATS.rx_bytes += len(pcm)
            STATS.rx_frames += 1
            STATS.rx_dbfs = compute_dbfs(pcm)
            self.device_link.on_audio_rx(pcm)

        elif kind == PKT_CALL_ACCEPT:
            print("[udp] ESP32 physical button pressed: ACCEPT CALL", flush=True)
            self.device_link.on_call_accept()

        elif kind == PKT_CALL_END:
            print("[udp] ESP32 physical button pressed: HANG UP", flush=True)
            self.device_link.on_call_end(notify_esp=False)

# ---------------------------------------------------------------- Downlink Pacer Queue

class DownlinkPacer:
    """Buffers incoming WebRTC frames and drains them at strict 20ms intervals."""
    def __init__(self, device_link: DeviceLink):
        self.device_link = device_link
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
                    if STATS.state == "IN_CALL" and not STATS.is_on_hold:
                        chunk = b"\x00" * FRAME_BYTES
                    else:
                        continue

                if not STATS.is_on_hold:
                    filtered = self.processor.process_pcm16(chunk)
                    self.device_link.send_audio(filtered)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[pacer] error: {e}", flush=True)

# ---------------------------------------------------------------- LiveKit Media Gateway

class LiveKitSession:
    """Server-side participant that bridges ESP32 audio <-> LiveKit Room."""
    def __init__(self, pacer: DownlinkPacer, on_empty_room=None):
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
            # No LiveKit session means no listener. Dropping here is correct, but
            # it used to happen silently, so a call that never connected looked
            # identical to one that connected and carried nothing.
            STATS.dropped_frames += 1
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

# ---------------------------------------------------------------- Telephone Manager

class TelephoneManager:
    def __init__(self):
        self.device_link = None
        self.pacer = None
        self.livekit = None
        self._watchdog_task = None

    async def init(self):
        loop = asyncio.get_running_loop()
        self.device_link = DeviceLink(
            on_audio_rx=self.on_device_audio,
            on_call_accept=self.on_button_accept,
            on_call_end=self.on_button_hangup
        )

        # Attempt to bind local UDP port 8081 (runs concurrently with WebSocket)
        try:
            udp_proto = UdpLinkProtocol(self.device_link)
            await loop.create_datagram_endpoint(lambda: udp_proto, local_addr=("0.0.0.0", UDP_PORT))
        except Exception as e:
            print(f"[udp] note: UDP bind ({UDP_PORT}) skipped or unavailable: {e}", flush=True)

        self.pacer = DownlinkPacer(self.device_link)
        self.pacer.start()

        self.livekit = LiveKitSession(
            self.pacer,
            on_empty_room=self.on_remote_empty
        )
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())

    async def _watchdog_loop(self):
        while True:
            try:
                await asyncio.sleep(2)
                now = time.time()
                if STATS.state == "RINGING" and STATS.ring_start_time:
                    if now - STATS.ring_start_time > RING_TIMEOUT_SEC:
                        print(f"[watchdog] Ringing timed out after {RING_TIMEOUT_SEC}s -> auto-cancelling", flush=True)
                        self.on_button_hangup(notify_esp=True)
                elif STATS.state in ("IN_CALL", "ON_HOLD"):
                    idle_sec = now - STATS.last_activity_time
                    if idle_sec > INACTIVITY_TIMEOUT_SEC:
                        print(f"[watchdog] Dead air silence detected ({idle_sec:.0f}s >= {INACTIVITY_TIMEOUT_SEC}s) -> releasing abandoned call", flush=True)
                        self.on_button_hangup(notify_esp=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[watchdog] error: {e}", flush=True)

    def on_remote_empty(self):
        print("[call] caller disconnected from LiveKit room -> releasing lock", flush=True)
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
            print("[livekit] disconnecting from room (preserving quota)", flush=True)
            await self.livekit.stop()
        try:
            lkapi = api.LiveKitAPI(LIVEKIT_URL, LIVEKIT_KEY, LIVEKIT_SECRET)
            await lkapi.room.delete_room(api.DeleteRoomRequest(room=ROOM_NAME))
            await lkapi.aclose()
            print(f"[livekit] deleted room '{ROOM_NAME}' to prevent orphan leaks and save quota", flush=True)
        except Exception as e:
            print(f"[livekit] notice deleting room: {e}", flush=True)

    def on_device_audio(self, pcm: bytes):
        STATS.last_activity_time = time.time()
        if STATS.state == "IN_CALL" and not STATS.is_on_hold:
            self.livekit.push_uplink(pcm)

    def set_hold(self, hold: bool):
        STATS.is_on_hold = hold
        if hold:
            set_state("ON_HOLD", "set_hold(true)")
            print(f"[call] call {STATS.active_call_id} placed on HOLD", flush=True)
        else:
            set_state("IN_CALL", "set_hold(false)")
            print(f"[call] call {STATS.active_call_id} resumed from HOLD", flush=True)
        notify_status_change()

    def promote_next_queued_caller(self):
        if not STATS.call_queue:
            return False
        next_caller = STATS.call_queue.pop(0)
        caller_id = next_caller["caller_id"]
        call_id = f"call_{int(time.time())}_{caller_id}"
        print(f"[queue] Promoting queued caller '{caller_id}' to active ringing call ({call_id})", flush=True)
        set_state("RINGING", "queued caller promoted")
        STATS.is_on_hold = False
        STATS.active_call_id = call_id
        STATS.active_caller_id = caller_id
        STATS.ring_start_time = time.time()
        STATS.last_activity_time = time.time()
        self.device_link.ring_device()
        asyncio.create_task(self.start_call_session())
        notify_status_change()
        return True

    def on_button_accept(self, notify_esp=True):
        """A call was answered.

        notify_esp=False is used when the ESP32 is the one that told us (its
        BOOT button or the earbud's own call button): it has already run
        hfp_call_accept() and would only be re-triggered by an echo.
        """
        print("[call] answered; connecting audio on-demand", flush=True)
        set_state("IN_CALL", "on_button_accept")
        STATS.is_on_hold = False
        STATS.call_start_time = time.time()
        STATS.ring_start_time = None
        STATS.last_activity_time = time.time()
        if notify_esp:
            self.device_link.send_call_accept()
        asyncio.create_task(self.start_call_session())
        notify_status_change()

    def on_button_hangup(self, notify_esp=True):
        print("[call] call ended: releasing listener lock", flush=True)
        set_state("IDLE", f"on_button_hangup notify_esp={notify_esp}")
        STATS.is_on_hold = False
        STATS.active_call_id = None
        STATS.active_caller_id = None
        STATS.caller_id = None
        STATS.target_ext = None
        STATS.call_direction = None
        STATS.call_start_time = None
        STATS.ring_start_time = None
        if notify_esp:
            self.device_link.send_call_end()
        asyncio.create_task(self.stop_call_session())
        notify_status_change()

        # If any caller is queued, promote them automatically after brief pause
        if STATS.call_queue:
            asyncio.get_running_loop().call_later(1.0, self.promote_next_queued_caller)

    async def initiate_outgoing_call_to_ext(self, target_ext: str):
        if STATS.state != "IDLE":
            print(f"[call] Cannot dial out: ESP32 is in state {STATS.state}", flush=True)
            self.device_link.send_call_busy()
            return

        entry = EXTENSIONS.get_by_extension(target_ext)
        if not entry:
            print(f"[call] Dial failed: Extension {target_ext} not registered", flush=True)
            self.device_link.send_call_busy()
            return

        ws = entry.get("ws")
        now = time.time()
        is_online = (ws is not None and not ws.closed) or (now - entry.get("last_seen", 0) < 120)
        if not is_online:
            print(f"[call] Dial failed: Extension {target_ext} is offline", flush=True)
            self.device_link.send_call_busy()
            return

        caller_id = "0000"
        call_id = f"call_{int(time.time())}_esp_to_{target_ext}"
        print(f"[call] ESP32 outgoing call to {target_ext} initiated ({call_id})", flush=True)

        set_state("RINGING", f"call_start_handler caller={caller_id}")
        STATS.active_call_id = call_id
        STATS.active_caller_id = "0000"
        STATS.caller_id = "0000"
        STATS.target_ext = target_ext
        STATS.call_direction = "from_esp"
        STATS.ring_start_time = time.time()
        STATS.last_activity_time = time.time()
        notify_status_change()

        # Connect LiveKit bridge session
        asyncio.create_task(self.start_call_session())

        # Generate credentials for mobile recipient
        cred = generate_caller_token(f"user_{target_ext}")

        # Send push notification over target's WebSocket
        if ws and not ws.closed:
            try:
                await ws.send_json({
                    "type": "incoming_call",
                    "call_id": call_id,
                    "caller_id": "0000",
                    "caller_name": "ESP32 ল্যান্ডলাইন",
                    "caller_ext": "0000",
                    "room": cred["room"],
                    "livekit_url": cred["url"],
                    "token": cred["token"]
                })
            except Exception as e:
                print(f"[call] Failed to notify extension {target_ext}: {e}", flush=True)

# ---------------------------------------------------------------- Token Generator

def generate_caller_token(caller_id: str):
    from livekit import api
    token = (api.AccessToken(LIVEKIT_KEY, LIVEKIT_SECRET)
             .with_identity(caller_id)
             .with_grants(api.VideoGrants(room_join=True, room=ROOM_NAME, can_publish=True, can_subscribe=True))
             .to_jwt())
    return {"url": LIVEKIT_URL, "token": token, "room": ROOM_NAME}

# ---------------------------------------------------------------- aiohttp Web Application

def create_app(mgr: TelephoneManager) -> web.Application:
    app = web.Application()

    @web.middleware
    async def cors_and_rate_middleware(request, handler):
        if request.method == "OPTIONS":
            return web.Response(
                status=204,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Auth-Token",
                    "Access-Control-Max-Age": "86400",
                }
            )

        # Rate limiting.
        #
        # Authenticated clients are NOT rate limited. The token is the credential,
        # and the device link holds a single long-lived WebSocket that legitimately
        # reconnects whenever Render or Cloudflare drops it; counting those
        # handshakes against a per-IP budget meant the ESP32 could lock itself out
        # permanently. Measured on this deployment: the device retried every 5 s,
        # each retry counted, and the limiter then answered *every* request from
        # that IP - including the retry - with HTTP 429 for 60 s. retry-after
        # equalled the retry interval, so the bucket was never allowed to drain
        # and the device could never reconnect.
        #
        # Unauthenticated traffic is still limited, which is what the limiter is
        # for: it exists to stop anonymous abuse of /token and /call/start.
        is_authenticated = check_auth(request)
        if not is_authenticated:
            xff = request.headers.get("cf-connecting-ip") or request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "")
            client_ip = xff.split(",")[0].strip() if xff else (request.remote or "unknown")
            is_call_op = request.path in ("/call/start", "/token")
            allowed, limit_msg = RATE_LIMITER.check(client_ip, is_call_op=is_call_op)
            if not allowed:
                return web.json_response(
                    {"error": "too_many_requests", "detail": limit_msg},
                    status=429,
                    headers={"Retry-After": "60", "Access-Control-Allow-Origin": "*"}
                )

        try:
            response = await handler(request)
        except web.HTTPException as ex:
            response = ex
        except Exception as e:
            print(f"[http] 500 error: {e}", flush=True)
            response = web.json_response({"error": "server_error", "detail": str(e)}, status=500)

        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Auth-Token"
        return response

    app.middlewares.append(cors_and_rate_middleware)

    CALL_LOCK = asyncio.Lock()

    # Routes
    async def ping_handler(request):
        return web.Response(text="pong")

    async def logs_handler(request):
        """Return captured bridge log lines, newest last.

        ?since=N returns only lines with seq > N, which makes it cheap to poll
        from a shell while reproducing a failure.
        """
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            since = int(request.query.get("since", "0"))
        except ValueError:
            since = 0
        try:
            limit = int(request.query.get("limit", "400"))
        except ValueError:
            limit = 400
        items = [{"seq": q, "t": t, "line": l}
                 for (q, t, l) in list(LOG_RING) if q > since][-limit:]
        return web.json_response({
            "seq": _log_seq,
            "count": len(items),
            "lines": items,
            "state": STATS.state,
        })

    async def status_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        return web.json_response(STATS.as_dict())

    async def devices_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        return web.json_response([STATS.as_dict()])

    async def call_start_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        target_ext = body.get("target_ext", "0000")
        caller_id = body.get("caller_id", "android-caller")
        caller_ext = body.get("caller_ext", "unknown")
        caller_name = body.get("caller_name", caller_id)

        # Direct mobile-to-mobile extension call
        if target_ext != "0000":
            entry = EXTENSIONS.get_by_extension(target_ext)
            if not entry:
                return web.json_response({"error": "not_found", "detail": f"Extension {target_ext} not registered"}, status=404)
            ws = entry.get("ws")
            now = time.time()
            is_online = (ws is not None and not ws.closed) or (now - entry.get("last_seen", 0) < 120)
            if not is_online:
                return web.json_response({"error": "offline", "detail": f"Extension {target_ext} is currently offline"}, status=404)

            room_name = f"room_{min(caller_ext, target_ext)}_{max(caller_ext, target_ext)}_{int(time.time())}"
            from livekit import api
            token_caller = (api.AccessToken(LIVEKIT_KEY, LIVEKIT_SECRET)
                            .with_identity(f"ext_{caller_ext}")
                            .with_name(caller_name)
                            .with_grants(api.VideoGrants(room_join=True, room=room_name, can_publish=True, can_subscribe=True))
                            .to_jwt())
            token_target = (api.AccessToken(LIVEKIT_KEY, LIVEKIT_SECRET)
                            .with_identity(f"ext_{target_ext}")
                            .with_name(entry.get("display_name", f"User {target_ext}"))
                            .with_grants(api.VideoGrants(room_join=True, room=room_name, can_publish=True, can_subscribe=True))
                            .to_jwt())

            call_id = f"p2p_{int(time.time())}_{caller_ext}_to_{target_ext}"
            if ws and not ws.closed:
                try:
                    await ws.send_json({
                        "type": "incoming_call",
                        "call_id": call_id,
                        "caller_id": caller_ext,
                        "caller_name": caller_name,
                        "caller_ext": caller_ext,
                        "room": room_name,
                        "livekit_url": LIVEKIT_URL,
                        "token": token_target
                    })
                except Exception as e:
                    print(f"[p2p] notification failed: {e}", flush=True)

            return web.json_response({
                "call_id": call_id,
                "caller_id": caller_id,
                "caller_ext": caller_ext,
                "target_ext": target_ext,
                "room": room_name,
                "livekit_url": LIVEKIT_URL,
                "token": token_caller,
                "expires_in": 3600
            })

        # Calls to ESP32 Landline (0000)
        async with CALL_LOCK:
            if STATS.state in ("IN_CALL", "RINGING", "ON_HOLD"):
                queue_requested = body.get("queue", False)

                if queue_requested:
                    if len(STATS.call_queue) >= 3:
                        return web.json_response({
                            "error": "queue_full",
                            "detail": "Call queue is full (max 3 waiting callers)",
                            "active_caller_id": STATS.active_caller_id
                        }, status=486)
                    
                    # Check if already in queue
                    existing = next((q for q in STATS.call_queue if q["caller_id"] == caller_id), None)
                    if not existing:
                        call_id = f"queue_{int(time.time())}_{caller_id}"
                        item = {
                            "call_id": call_id,
                            "caller_id": caller_id,
                            "queued_at": time.time(),
                            "status": "queued"
                        }
                        STATS.call_queue.append(item)
                    else:
                        item = existing
                    
                    pos = STATS.call_queue.index(item) + 1
                    print(f"[queue] Caller '{caller_id}' queued at position {pos}", flush=True)
                    return web.json_response({
                        "status": "queued",
                        "call_id": item["call_id"],
                        "caller_id": caller_id,
                        "queue_position": pos,
                        "target_device": DEVICE_ID
                    }, status=202)

                return web.json_response({
                    "error": "busy",
                    "detail": "ESP32 listener is currently on another call",
                    "active_call_id": STATS.active_call_id,
                    "active_caller_id": STATS.active_caller_id,
                    "queue_len": len(STATS.call_queue)
                }, status=486)

            call_id = f"call_{int(time.time())}_{caller_id}"
            print(f"[call] Reserved for caller '{caller_id}' (call_id={call_id})", flush=True)

            set_state("RINGING", f"call_start_handler caller={caller_id}")
            STATS.active_call_id = call_id
            STATS.active_caller_id = caller_id
            STATS.caller_id = caller_id
            STATS.target_ext = target_ext
            STATS.call_direction = "to_esp"
            STATS.ring_start_time = time.time()
            notify_status_change()

            mgr.device_link.ring_device()
            asyncio.create_task(mgr.start_call_session())

            cred = generate_caller_token(caller_id)
            return web.json_response({
                "call_id": call_id,
                "caller_id": caller_id,
                "target_device": DEVICE_ID,
                "room": cred["room"],
                "livekit_url": cred["url"],
                "token": cred["token"],
                "expires_in": 3600
            })

    async def _hangup_after_grace(dropped_ws):
        await asyncio.sleep(DEVICE_OFFLINE_GRACE_SEC)
        if mgr.device_link.ws is not None:
            return                      # came back; keep the call
        if STATS.state == "IDLE":
            return
        print("[ws] device did not return; releasing the call", flush=True)
        mgr.on_button_hangup(notify_esp=False)
        notify_status_change()

    async def call_end_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        async with CALL_LOCK:
            mgr.on_button_hangup()
        return web.json_response({"status": "ended", "device": DEVICE_ID})

    async def call_hold_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        if STATS.state not in ("IN_CALL", "ON_HOLD"):
            return web.json_response({"error": "not_in_call", "detail": "No active call to hold or resume"}, status=400)
        
        hold = True
        try:
            body = await request.json()
            hold = body.get("hold", not STATS.is_on_hold)
        except Exception:
            hold = not STATS.is_on_hold
        
        mgr.set_hold(hold)
        return web.json_response({
            "status": "holding" if hold else "active",
            "on_hold": hold,
            "call_id": STATS.active_call_id
        })

    async def call_reject_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        caller_id = None
        try:
            body = await request.json()
            caller_id = body.get("caller_id")
        except Exception:
            pass
        
        async with CALL_LOCK:
            if STATS.state == "RINGING":
                print(f"[call] Ringing call rejected by client '{caller_id}' (active was '{STATS.active_caller_id}')", flush=True)
                mgr.on_button_hangup()
                return web.json_response({"status": "rejected", "detail": "call rejected"})
            
            if caller_id:
                STATS.call_queue = [q for q in STATS.call_queue if q["caller_id"] != caller_id]
                print(f"[queue] Removed caller '{caller_id}' from queue upon reject/cancel", flush=True)
                return web.json_response({"status": "dequeued", "caller_id": caller_id})
        
        return web.json_response({"status": "ok", "state": STATS.state.lower()})

    async def call_poll_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        
        caller_id = request.query.get("caller_id", "")
        call_id = request.query.get("call_id", "")
        
        is_active = (caller_id and STATS.active_caller_id == caller_id) or (call_id and STATS.active_call_id == call_id)
        
        queue_pos = -1
        in_queue = False
        for idx, q in enumerate(STATS.call_queue):
            if (caller_id and q["caller_id"] == caller_id) or (call_id and q["call_id"] == call_id):
                queue_pos = idx + 1
                in_queue = True
                break
        
        token_info = None
        if is_active and STATS.state in ("RINGING", "IN_CALL", "ON_HOLD"):
            cred = generate_caller_token(caller_id or STATS.active_caller_id or "android-caller")
            token_info = {
                "room": cred["room"],
                "livekit_url": cred["url"],
                "token": cred["token"]
            }

        return web.json_response({
            "state": STATS.state.lower(),
            "availability": "available" if STATS.state == "IDLE" else "busy",
            "is_active_caller": is_active,
            "active_call_id": STATS.active_call_id,
            "active_caller_id": STATS.active_caller_id,
            "on_hold": STATS.is_on_hold,
            "in_queue": in_queue,
            "queue_position": queue_pos,
            "queue_len": len(STATS.call_queue),
            "credentials": token_info
        })

    async def call_accept_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        if STATS.state == "RINGING":
            mgr.on_button_accept()
            return web.json_response({"status": "accepted", "call_id": STATS.active_call_id})
        return web.json_response({"status": "ignored", "state": STATS.state.lower()})

    async def extensions_list_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        return web.json_response(EXTENSIONS.list_extensions())

    async def extensions_register_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid_json"}, status=400)

        ext = body.get("extension", "").strip()
        client_id = body.get("client_id", "").strip()
        display_name = body.get("display_name", "").strip()

        if not client_id:
            return web.json_response({"error": "missing_fields", "detail": "client_id is required"}, status=400)

        ok, msg, assigned_ext = EXTENSIONS.register(ext, client_id, display_name)
        if not ok:
            return web.json_response({"error": "conflict", "detail": msg}, status=409)

        notify_extensions_change(mgr.device_link)
        return web.json_response({
            "status": "ok",
            "message": msg,
            "extension": assigned_ext,
            "client_id": client_id,
            "display_name": display_name,
            "extensions": EXTENSIONS.list_extensions()
        })

    async def extensions_assign_handler(request):
        """Auto-assigns or returns the unique permanent sequential extension for a client_id (Hotel Check-In)."""
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        client_id = request.query.get("client_id", "").strip()
        display_name = request.query.get("display_name", "").strip()
        requested_ext = request.query.get("extension", "").strip()

        if request.can_read_body:
            try:
                body = await request.json()
                client_id = body.get("client_id", client_id).strip()
                display_name = body.get("display_name", display_name).strip()
                requested_ext = body.get("extension", requested_ext).strip()
            except Exception:
                pass

        if not client_id:
            return web.json_response({"error": "missing_fields", "detail": "client_id is required"}, status=400)

        assigned_ext, is_new = EXTENSIONS.get_or_assign(client_id, display_name, requested_ext=requested_ext)
        notify_extensions_change(mgr.device_link)
        return web.json_response({
            "status": "assigned",
            "is_new": is_new,
            "extension": assigned_ext,
            "client_id": client_id,
            "display_name": display_name or f"User {assigned_ext}",
            "extensions": EXTENSIONS.list_extensions()
        })

    async def extensions_deregister_handler(request):
        if not check_auth(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid_json"}, status=400)

        ext = body.get("extension", "").strip()
        client_id = body.get("client_id", "").strip()

        ok = EXTENSIONS.deregister(ext, client_id)
        if ok:
            notify_extensions_change(mgr.device_link)
            return web.json_response({"status": "ok", "message": "Deregistered"})
        return web.json_response({"error": "not_found", "detail": "Extension or client_id mismatch"}, status=404)

    # Direct WebSocket Connection for ESP32 Hardware
    async def esp32_ws_handler(request):
        if not check_auth(request):
            return web.Response(status=401, text="Unauthorized: invalid auth token")

        ws = web.WebSocketResponse(heartbeat=15.0, max_msg_size=1024 * 64)
        await ws.prepare(request)
        remote_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.remote or "unknown"
        print(f"[ws] ESP32 hardware connected directly to cloud from {remote_ip}!", flush=True)

        mgr.device_link.ws = ws
        STATS.device_addr = (remote_ip, 443)

        # DO NOT RESET THE CALL STATE ON RECONNECT.
        #
        # This used to be an unconditional STATS.state = "IDLE", which is why a
        # call rang for a few seconds and then "closed itself": the device's
        # WebSocket reconnects routinely (Render's proxy cycles the socket, and
        # so does the ESP32 when it re-associates), and every reconnect silently
        # cancelled whatever call was in progress. Seen in the field as
        # "it receives the ring but auto-closes".
        #
        # The link coming back is a link event, not a call event. Only adopt
        # IDLE when we have no call to preserve. If a call IS in progress the
        # device is still the same device, so re-arm it: re-send the ring (or
        # tell it the far end already answered) so its OLED and buzzer match the
        # bridge's state instead of being left stranded.
        if STATS.state == "IDLE":
            notify_status_change()
        else:
            print(f"[ws] reconnect during {STATS.state}; preserving the call", flush=True)
            if STATS.state == "RINGING":
                mgr.device_link.ring_device()
            elif STATS.state in ("IN_CALL", "ON_HOLD"):
                mgr.device_link.send_call_accept()
            notify_status_change()
        mgr.device_link.send_extension_list()

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.BINARY:
                    data = msg.data
                    if not data:
                        continue
                    kind = data[0]
                    if kind == PKT_AUDIO:
                        pcm = data[1:]
                        STATS.rx_bytes += len(pcm)
                        STATS.rx_frames += 1
                        STATS.rx_dbfs = compute_dbfs(pcm)
                        mgr.on_device_audio(pcm)
                    elif kind == PKT_CALL_ACCEPT:
                        print("[ws] ESP32 physical button pressed: ACCEPT CALL", flush=True)
                        mgr.on_button_accept(notify_esp=False)
                    elif kind == PKT_CALL_END:
                        print("[ws] ESP32 physical button pressed: HANG UP", flush=True)
                        mgr.on_button_hangup(notify_esp=False)
                    elif kind == PKT_CALL_DIAL:
                        target_ext = data[1:5].decode("ascii", errors="ignore")
                        print(f"[ws] ESP32 physical dial: outgoing call to extension {target_ext}", flush=True)
                        asyncio.create_task(mgr.initiate_outgoing_call_to_ext(target_ext))
                    elif kind == PKT_HEALTH:
                        # type + 3 x u32 LE + u8 reset reason
                        if len(data) >= 14:
                            boots, browns, heap = struct.unpack_from("<III", data, 1)
                            reason = data[13]
                            prev = STATS.dev_boot_count
                            STATS.dev_boot_count = boots
                            STATS.dev_brownouts = browns
                            STATS.dev_free_heap = heap
                            STATS.dev_reset_reason = reason
                            STATS.dev_connects += 1
                            if prev is not None and boots > prev:
                                print(f"[device] RESET detected: boot #{prev} -> #{boots} "
                                      f"(brownouts={browns}, reason={reason}, heap={heap})",
                                      flush=True)
                            else:
                                print(f"[device] health: boot #{boots}, brownouts={browns}, "
                                      f"free_heap={heap}, reset_reason={reason}", flush=True)
                    elif kind == PKT_PING:
                        await ws.send_bytes(bytes([PKT_PONG]))
                    elif kind == PKT_CONTROL:
                        await ws.send_bytes(bytes([PKT_CONTROL]) + b"HERE")
                elif msg.type == web.WSMsgType.ERROR:
                    print(f"[ws] connection error: {ws.exception()}", flush=True)
        finally:
            print("[ws] ESP32 disconnected from cloud", flush=True)
            if mgr.device_link.ws is ws:
                mgr.device_link.ws = None
                STATS.device_addr = None
                if STATS.state != "IDLE":
                    # DO NOT hang up yet.
                    #
                    # This used to call on_button_hangup() immediately, which
                    # made every transport blip look like the caller hanging up.
                    # Measured during a call: the device reconnects (the socket
                    # had been dropped, the link did not fail), the finally block
                    # runs first, the call is torn down and the reconnect lands
                    # in IDLE. From the phone that reads as "the call closed
                    # itself after a few seconds".
                    #
                    # A landline must tolerate a brief loss of the line. Give it
                    # DEVICE_OFFLINE_GRACE_SEC to come back; only a real absence
                    # is treated as the far end disappearing.
                    print(f"[ws] call preserved for {DEVICE_OFFLINE_GRACE_SEC}s "
                          f"awaiting reconnect", flush=True)
                    asyncio.create_task(_hangup_after_grace(ws))
                notify_status_change()

        return ws

    # Real-time WebSocket Status Push for Android Clients
    async def client_ws_handler(request):
        if not check_auth(request):
            return web.Response(status=401, text="Unauthorized: invalid auth token")

        ws = web.WebSocketResponse(heartbeat=20.0)
        await ws.prepare(request)
        CLIENT_WEBSOCKETS.add(ws)
        registered_ext = None
        registered_client_id = None
        try:
            # Immediately send initial state & registered extensions
            await ws.send_json(STATS.as_dict())
            await ws.send_json({
                "type": "extensions_update",
                "extensions": EXTENSIONS.list_extensions()
            })
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    if msg.data == "ping":
                        await ws.send_str("pong")
                    else:
                        try:
                            payload = json.loads(msg.data)
                            msg_type = payload.get("type")
                            if msg_type == "register":
                                ext = payload.get("extension", "").strip()
                                cid = payload.get("client_id", "").strip()
                                dname = payload.get("display_name", "").strip()
                                if cid:
                                    ok, m, assigned_ext = EXTENSIONS.register(ext, cid, dname, ws=ws)
                                    if ok:
                                        registered_ext = assigned_ext
                                        registered_client_id = cid
                                        notify_extensions_change(mgr.device_link)
                                        await ws.send_json({
                                            "type": "register_ack",
                                            "success": True,
                                            "extension": assigned_ext,
                                            "client_id": cid,
                                            "display_name": dname
                                        })
                                    else:
                                        await ws.send_json({"type": "register_ack", "success": False, "detail": m})
                            elif msg_type == "heartbeat":
                                cid = payload.get("client_id")
                                if cid:
                                    EXTENSIONS.heartbeat(cid)
                                await ws.send_str("pong")
                        except Exception:
                            pass
        finally:
            CLIENT_WEBSOCKETS.discard(ws)
            if registered_ext and registered_client_id:
                entry = EXTENSIONS.get_by_extension(registered_ext)
                if entry and entry.get("client_id") == registered_client_id:
                    entry["ws"] = None
                    notify_extensions_change(mgr.device_link)

        return ws

    async def root_handler(request):
        return web.json_response({
            "service": "esp-telephone-backend",
            "mode": "native-android-api-only",
            "version": "1.0.0",
            "device": DEVICE_ID,
            "status": "online"
        })

    async def admin_reset_handler(request):
        """Private development reset endpoint. Completely resets active calls, queues, LiveKit rooms, and rate limits."""
        if not check_auth(request):
            return web.json_response({"error": "unauthorized", "detail": "Valid authentication required"}, status=401)

        clear_exts = False
        try:
            if request.can_read_body:
                body = await request.json()
                clear_exts = body.get("clear_extensions", False)
        except Exception:
            pass

        async with CALL_LOCK:
            print("[admin] Development Reset initiated via /admin/reset API", flush=True)

            # 1. Reset state machine & call records
            prev_call_id = STATS.active_call_id
            set_state("IDLE", "admin reset")
            STATS.is_on_hold = False
            STATS.active_call_id = None
            STATS.active_caller_id = None
            STATS.caller_id = None
            STATS.target_ext = None
            STATS.call_direction = None
            STATS.call_start_time = None
            STATS.ring_start_time = None
            STATS.call_queue.clear()
            STATS.last_activity_time = time.time()

            # 2. Stop LiveKit session & delete orphaned rooms
            await mgr.stop_call_session()

            # 3. Inform ESP32 hardware to terminate ringing/call
            mgr.device_link.send_call_end()

            # 4. Flush rate limit counters
            RATE_LIMITER.clear()

            # 5. Flush extensions if explicitly requested
            if clear_exts:
                EXTENSIONS.extensions.clear()
                notify_extensions_change(mgr.device_link)

            # 6. Broadcast clean status to all active WebSocket clients
            notify_status_change()

        return web.json_response({
            "status": "reset_success",
            "timestamp": time.time(),
            "device": DEVICE_ID,
            "device_state": STATS.state,
            "cleared_call_id": prev_call_id,
            "call_queue_length": len(STATS.call_queue),
            "rate_limits_cleared": True,
            "extensions_cleared": clear_exts,
            "message": "Gateway state, active calls, queues, and rate limits have been completely reset."
        })

    app.router.add_get("/ping", ping_handler)
    app.router.add_get("/status", status_handler)
    app.router.add_get("/logs", logs_handler)
    app.router.add_get("/devices", devices_handler)
    app.router.add_post("/call/start", call_start_handler)
    app.router.add_post("/call/end", call_end_handler)
    app.router.add_post("/call/hold", call_hold_handler)
    app.router.add_post("/call/reject", call_reject_handler)
    app.router.add_get("/call/poll", call_poll_handler)
    app.router.add_post("/call/accept", call_accept_handler)
    app.router.add_get("/extensions", extensions_list_handler)
    app.router.add_get("/extensions/assign", extensions_assign_handler)
    app.router.add_post("/extensions/assign", extensions_assign_handler)
    app.router.add_post("/extensions/register", extensions_register_handler)
    app.router.add_post("/extensions/deregister", extensions_deregister_handler)
    app.router.add_post("/hangup", call_end_handler)
    app.router.add_post("/admin/reset", admin_reset_handler)
    app.router.add_get("/admin/reset", admin_reset_handler)
    app.router.add_post("/system/reset", admin_reset_handler)
    app.router.add_get("/system/reset", admin_reset_handler)
    app.router.add_post("/dev/reset", admin_reset_handler)
    app.router.add_get("/dev/reset", admin_reset_handler)
    app.router.add_get("/esp32/ws", esp32_ws_handler)
    app.router.add_get("/client/ws", client_ws_handler)
    app.router.add_get("/", root_handler)

    return app

# ---------------------------------------------------------------- Entrypoint

async def main():
    mgr = TelephoneManager()
    await mgr.init()

    STATS.state = "IDLE"
    print(f"[backend] ESP32 Internet Calling Gateway started on port {HTTP_PORT}", flush=True)
    print(f"[backend] Dead-Air Silence Safeguard active (INACTIVITY_TIMEOUT={INACTIVITY_TIMEOUT_SEC}s, RING_TIMEOUT={RING_TIMEOUT_SEC}s)", flush=True)
    print(f"[backend] Direct WebSocket & REST API enabled at /esp32/ws, /client/ws and /call/*", flush=True)

    app = create_app(mgr)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()

    async def self_keepalive():
        """Keeps Render free instance awake by pinging external URL every 10 minutes."""
        base_url = os.environ.get("RENDER_EXTERNAL_URL", "https://esp-audio.onrender.com").rstrip("/")
        ping_url = f"{base_url}/ping"
        print(f"[keepalive] Self-ping watchdog activated for {ping_url} (interval: 480s)", flush=True)
        await asyncio.sleep(30)
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    async with session.get(ping_url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        if resp.status == 200:
                            print(f"[keepalive] Self-ping OK ({ping_url} -> 200)", flush=True)
                        else:
                            print(f"[keepalive] Self-ping returned status {resp.status}", flush=True)
                except asyncio.CancelledError:
                    break
                except Exception as err:
                    print(f"[keepalive] Self-ping failed: {err}", flush=True)
                await asyncio.sleep(480)

    keepalive_task = asyncio.create_task(self_keepalive())

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop_event.set)

    await stop_event.wait()
    print("[backend] shutting down...", flush=True)
    keepalive_task.cancel()
    await runner.cleanup()
    await mgr.livekit.stop()
    mgr.pacer.stop()

if __name__ == "__main__":
    asyncio.run(main())
