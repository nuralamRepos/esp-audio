# ESP Telephone Cloud Bridge

Real-time audio bridge connecting **LiveKit Cloud WebRTC** with an **ESP32 Bluetooth Landline Intercom**.

## Features
- **Pure WebRTC Media Bridge**: LiveKit Cloud <-> ESP32 (16 kHz raw PCM).
- **Google Meet-style Web Interface**: Join calls directly from any browser (Android Chrome, iOS Safari) with full native audio.
- **Render Ready**: Automatic deployment via `Dockerfile` and `render.yaml`.
- **Zero-Sleep Keepalive**: Supports `GET /ping` for 24/7 free tier operation.

## Environment Variables
- `LIVEKIT_URL`: LiveKit Cloud WebSocket URL (`wss://...`)
- `LIVEKIT_API_KEY`: LiveKit Project API Key
- `LIVEKIT_API_SECRET`: LiveKit Project API Secret
- `LIVEKIT_ROOM`: Target room name (default: `landline`)
- `PORT`: HTTP port assigned by cloud host (default: `8080`)
