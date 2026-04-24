import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Optional

import requests
from bleak import BleakClient, BleakScanner


# ============================================================
# CONFIG (edit these)
# ============================================================
DEVICE_NAME_SUBSTRING = os.getenv("BLE_DEVICE_NAME", "SmartToolbox")
# If you know the MAC (Linux) / UUID (macOS), set it here to skip scanning:
DEVICE_ADDRESS = os.getenv("BLE_DEVICE_ADDRESS", "").strip()

SERVICE_UUID = os.getenv("BLE_SERVICE_UUID", "4fafc201-1fb5-459e-8fcc-c5c9c331914b")
CHAR_UUID = os.getenv("BLE_CHAR_UUID", "beb5483e-36e1-4688-b7f5-ea07361b26a8")

# Server webhook that will ingest events (partner builds it)
SERVER_WEBHOOK_URL = os.getenv("SERVER_WEBHOOK_URL", "http://localhost:8080/toolbox/events")

# Optional shared secret header (recommended even if payload is plaintext)
WEBHOOK_SHARED_SECRET = os.getenv("WEBHOOK_SHARED_SECRET", "").strip()

# Timeouts / retries
SCAN_TIMEOUT_SEC = float(os.getenv("SCAN_TIMEOUT_SEC", "10"))
CONNECT_TIMEOUT_SEC = float(os.getenv("CONNECT_TIMEOUT_SEC", "15"))
POST_TIMEOUT_SEC = float(os.getenv("POST_TIMEOUT_SEC", "5"))
RECONNECT_DELAY_SEC = float(os.getenv("RECONNECT_DELAY_SEC", "2"))
MAX_POST_RETRIES = int(os.getenv("MAX_POST_RETRIES", "5"))


@dataclass
class ForwarderState:
    last_seen: float = 0.0
    connected: bool = False
    device_addr: Optional[str] = None


def build_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if WEBHOOK_SHARED_SECRET:
        headers["X-Toolbox-Secret"] = WEBHOOK_SHARED_SECRET
    return headers


def post_event(payload: dict) -> None:
    """
    Send event to server webhook. Payload is sent "as-is" in plaintext JSON.
    Retries with exponential backoff on transient errors.
    """
    headers = build_headers()
    body = json.dumps(payload)

    delay = 0.5
    for attempt in range(1, MAX_POST_RETRIES + 1):
        try:
            r = requests.post(
                SERVER_WEBHOOK_URL,
                data=body,
                headers=headers,
                timeout=POST_TIMEOUT_SEC,
            )
            if 200 <= r.status_code < 300:
                return
            # Treat non-2xx as failure; show response for debugging
            print(f"[HTTP] attempt {attempt} status={r.status_code} resp={r.text[:200]}")
        except Exception as e:
            print(f"[HTTP] attempt {attempt} error: {e}")

        time.sleep(delay)
        delay = min(delay * 2, 10)

    print("[HTTP] ERROR: failed to deliver event after retries.")


def parse_toolbox_message(raw: bytes) -> Optional[dict]:
    """
    Toolbox firmware sends JSON strings like:
      {"event":"login","user":"Bob"}
      {"event":"checkout","user":"Bob","tool":"Tool1"}
      {"event":"return","tool":"Tool1"}
      {"event":"inventory","tools":[...]}
    We forward exactly that payload.
    """
    try:
        text = raw.decode("utf-8", errors="strict").strip()
        if not text:
            return None
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return None

        # Add metadata useful for server/app pipeline
        payload["_source"] = "ble_forwarder"
        payload["_ts"] = time.time()
        return payload
    except Exception as e:
        # If firmware ever sends non-JSON, you can log and ignore it
        print(f"[PARSE] ignored non-JSON message: {e}")
        return None


async def find_device_address() -> str:
    """
    Find the device address either from env var or by scanning for name substring.
    """
    if DEVICE_ADDRESS:
        return DEVICE_ADDRESS

    print(f"[BLE] Scanning {SCAN_TIMEOUT_SEC}s for device name containing '{DEVICE_NAME_SUBSTRING}'...")
    devices = await BleakScanner.discover(timeout=SCAN_TIMEOUT_SEC)
    for d in devices:
        name = (d.name or "").strip()
        if DEVICE_NAME_SUBSTRING.lower() in name.lower():
            print(f"[BLE] Found: name='{name}' addr='{d.address}'")
            return d.address

    raise RuntimeError(f"BLE device not found (name contains '{DEVICE_NAME_SUBSTRING}'). "
                       f"Set BLE_DEVICE_ADDRESS to skip scanning.")


async def run_forwarder(state: ForwarderState, stop_event: asyncio.Event) -> None:
    """
    Connect to BLE device, subscribe to notifications, forward received messages to server.
    Reconnect on disconnect.
    """
    while not stop_event.is_set():
        try:
            addr = await find_device_address()
            state.device_addr = addr

            print(f"[BLE] Connecting to {addr} ...")
            async with BleakClient(addr, timeout=CONNECT_TIMEOUT_SEC) as client:
                state.connected = True
                print("[BLE] Connected.")

                # Ensure service/char exists (optional sanity check)
                svcs = await client.get_services()
                if SERVICE_UUID and SERVICE_UUID.lower() not in [s.uuid.lower() for s in svcs]:
                    print("[BLE] Warning: Service UUID not found in advertised services list "
                          "(might still work if characteristic UUID is correct).")

                def handle_notify(_: int, data: bytearray):
                    payload = parse_toolbox_message(bytes(data))
                    if payload is None:
                        return
                    print(f"[BLE] RX: {payload}")
                    post_event(payload)
                    state.last_seen = time.time()

                print(f"[BLE] Subscribing to notifications on {CHAR_UUID} ...")
                await client.start_notify(CHAR_UUID, handle_notify)

                # Keep alive until stop requested or disconnected
                while not stop_event.is_set() and client.is_connected:
                    await asyncio.sleep(0.5)

                print("[BLE] Disconnected.")
                state.connected = False

        except Exception as e:
            state.connected = False
            print(f"[BLE] Error: {e}")

        if not stop_event.is_set():
            await asyncio.sleep(RECONNECT_DELAY_SEC)


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    def _handler(*_):
        print("\n[SYS] Stop requested.")
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
    except Exception:
        # Some environments don't allow signal handlers
        pass


async def main() -> None:
    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)

    state = ForwarderState()
    await run_forwarder(state, stop_event)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
