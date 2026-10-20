"""Gear Guard live cameras: start a live session like the Rivian app and watch it in a browser.

The app's flow, confirmed from its live traffic (captured with mitmproxy) and reproduced on the
vehicle with our own key:
1. Wake the vehicle and turn on video monitoring with the signed
   `security.video_monitoring.enable_video_monitoring` operation; wait until it reports on.
2. Pick a fresh random request id (16 bytes). Open the `gearGuardLiveConfig` GraphQL subscription
   with `commandId` = that request id as 32 lowercase hex chars (no dashes).
3. Send the signed `security.video_monitoring.start_live_streaming` operation, using that SAME
   request id as the parallax message's request id (fields 3 and 16), and settings
   {1: camera, 2: device id}. The cloud routes the Kinesis WebRTC config to the subscription whose
   commandId matches the request id, and the vehicle streams the chosen camera.
4. The video flows peer-to-peer over WebRTC. Browsers speak WebRTC natively, so we serve a tiny
   local page that joins the Kinesis signaling channel as the viewer and shows the camera track.

The correlation key is the request id (not the device id): the subscription's commandId must equal
the start op's request id, both as 32-hex. The device id (field 2) must be a registered Gear Guard
streaming device for the account (the phone the app runs on); capture it once from the app's traffic.
Steps 1 and 3 are signed with the paired key.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
import webbrowser

from protocol import f_len, f_var, parse_fields

ENABLE_OP = "security.video_monitoring.enable_video_monitoring"
STATE_TOPIC = "security.video_monitoring.state"
START_OP = "security.video_monitoring.start_live_streaming"

# The app's subscription, verbatim from its traffic (GearGuardLiveConfigSubscription).
SUB_QUERY = ("subscription GearGuardLiveConfigSubscription($vehicleId: String!, $commandId: String!) "
             "{ gearGuardLiveConfig(vehicleId: $vehicleId, commandId: $commandId) { __typename endpoint "
             "channelArn role iceServers { __typename url username credential ttl } } }")

# RivianMotionCamera selector values (field 1 of start_live_streaming settings).
CAMERAS = {"front": 1, "bed": 2, "left": 3, "right": 4, "rear": 5, "interior": 6}


def new_request():
    """A fresh (request_id bytes, commandId hex) pair. commandId is the request id as 32 lowercase
    hex chars — the exact form the app uses and the cloud correlates the config subscription on."""
    request_id = os.urandom(16)
    return request_id, request_id.hex()


def start_params(device_id, camera=CAMERAS["front"]):
    """Field-4 settings of start_live_streaming: {1: camera selector, 2: device id}."""
    return f_var(1, camera) + f_len(2, device_id.encode())


def _signed_start(op, params, vehicle_id, identity_id, secret, request_id):
    """Signed SendParallaxPayload body (base64), with a caller-chosen request id so it can be reused
    as the subscription commandId. Same layout as halloween.payload, request id fixed by the caller."""
    now = time.time()
    stamp = f_var(1, int(now)) + f_var(2, int((now % 1) * 1e9))
    command = (f_len(1, op.encode()) + f_var(2, 3) + f_len(3, request_id) +
               (f_len(4, params) if params else b"") + f_len(5, stamp) + f_len(7, vehicle_id.encode()))
    mac = hmac.new(secret, command, hashlib.sha256).digest()
    signature = f_len(1, f_var(1, 1) + f_len(2, mac)) + f_len(2, identity_id.encode())
    body = f_len(10, f_len(2, command)) + f_len(12, stamp) + f_len(16, request_id) + f_len(17, signature)
    return base64.b64encode(body).decode()


async def send_start(api, key, secret, device_id, camera, request_id):
    """Send the signed start_live_streaming with a fixed request id. True = accepted by the cloud."""
    from rivian.rivian import BASE_HEADERS, GRAPHQL_GATEWAY  # not exported; POC shortcut
    payload = _signed_start(START_OP, start_params(device_id, camera), key["vehicle_id"],
                            key["identity_id"], secret, request_id)
    body = {
        "operationName": "SendParallaxPayload",
        "query": "mutation SendParallaxPayload($payload: String!, $meta: ParallaxMetaInput!) "
                 "{ sendParallaxPayload(payload: $payload, meta: $meta) { __typename success } }",
        "variables": {"payload": payload,
                      "meta": {"isVehicleModelOp": True, "model": START_OP, "requiresWakeup": True,
                               "vehicleId": key["vehicle_id"]}},
    }
    headers = BASE_HEADERS | {"Csrf-Token": api._csrf_token, "A-Sess": api._app_session_token,
                              "U-Sess": api._user_session_token}
    response = await api._Rivian__graphql_query(headers, GRAPHQL_GATEWAY, body)
    return bool(((await response.json()).get("data") or {}).get("sendParallaxPayload", {}).get("success"))


def video_monitoring_on(state):
    """True when the vehicle's video_monitoring.state says monitoring is on (field 1 == 2)."""
    return parse_fields(state).get(1) == [2]


class ConfigWatcher:
    """Open the gearGuardLiveConfig subscription for one command id and capture the first config
    the vehicle publishes on it. Used like TripWatcher: `async with ConfigWatcher(...) as w:`."""

    def __init__(self, api, vehicle_id, command_id):
        # command_id must equal the start op's request id (32-hex); the cloud routes the config here.
        self.api, self.vehicle_id, self.command_id = api, vehicle_id, command_id
        self.config, self._got, self._stop = None, asyncio.Event(), None

    async def __aenter__(self):
        payload = {
            "operationName": "GearGuardLiveConfigSubscription",
            "query": SUB_QUERY,
            "variables": {"vehicleId": self.vehicle_id, "commandId": self.command_id},
        }
        self._stop = await self.api._start_subscription(  # same entry point the library's own subscribe_* use
            payload, self._on_message, f"{self.vehicle_id} gearGuardLiveConfig")
        if self._stop is None:
            raise RuntimeError("couldn't open the gearGuardLiveConfig subscription (see the debug log)")
        return self

    async def __aexit__(self, *exc):
        if self._stop:
            await self._stop()

    def _on_message(self, message):
        config = ((message.get("payload") or {}).get("data") or {}).get("gearGuardLiveConfig")
        if config and config.get("endpoint"):
            self.config = config
            self._got.set()

    async def wait(self, timeout):
        """Return the config dict, or None on timeout."""
        try:
            await asyncio.wait_for(self._got.wait(), timeout)
        except TimeoutError:
            return None
        return self.config


# ── browser viewer ───────────────────────────────────────────────────
PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Gear Guard live</title>
<style>
  :root { color-scheme: dark; }
  body { background:#0b0d10; color:#dfe3e8; font:14px system-ui,sans-serif; margin:0; padding:16px; }
  h3 { margin:0 0 4px; font-weight:600; }
  #status { color:#8aa; margin-bottom:12px; }
  #videos { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:10px; }
  video { width:100%; background:#000; border-radius:8px; aspect-ratio:16/9; object-fit:contain; }
  #log { white-space:pre-wrap; font:12px ui-monospace,SFMono-Regular,monospace; color:#7fae7f;
         margin-top:14px; max-height:30vh; overflow:auto; border-top:1px solid #222; padding-top:8px; }
</style></head><body>
<h3>Gear Guard live</h3>
<div id="status">connecting to the vehicle's camera stream…</div>
<div id="videos"></div>
<div id="log"></div>
<script>
const cfg = __CONFIG__;
const CLIENT_ID = "ConsumerViewer";   // the app tags its signaling with this; the master answers it
const statusEl = document.getElementById('status');
const videosEl = document.getElementById('videos');
const logEl = document.getElementById('log');
function log(...a){
  const m = a.map(x => typeof x === 'string' ? x : JSON.stringify(x)).join(' ');
  logEl.textContent += m + '\n'; logEl.scrollTop = logEl.scrollHeight;
  fetch('/log', {method:'POST', body:m}).catch(()=>{});
}
function setStatus(s){ statusEl.textContent = s; }

// Kinesis returns iceServers with a `url` array; WebRTC wants `urls`.
const iceServers = (cfg.iceServers || []).map(s => {
  const o = { urls: s.url };
  if (s.username) o.username = s.username;
  if (s.credential) o.credential = s.credential;
  return o;
});
log('ICE servers:', iceServers.length, '(role ' + cfg.role + ')');

const pc = new RTCPeerConnection({ iceServers, bundlePolicy:'max-bundle' });
let remoteReady = false;
const pendingCandidates = [];
let masterClientId = null;

// The vehicle is the WebRTC "master"; we only receive.
pc.addTransceiver('video', { direction:'recvonly' });
pc.addTransceiver('audio', { direction:'recvonly' });

const streams = {};  // stream id -> <video>
pc.ontrack = (e) => {
  const stream = e.streams[0] || new MediaStream([e.track]);
  if (!streams[stream.id]) {
    const v = document.createElement('video');
    v.autoplay = true; v.playsInline = true; v.muted = true; v.controls = true;
    v.srcObject = stream;
    videosEl.appendChild(v);
    streams[stream.id] = v;
    log('track:', e.track.kind, 'stream', stream.id.slice(0,8));
    setStatus('receiving video — ' + Object.keys(streams).length + ' stream(s)');
  }
};
pc.onconnectionstatechange = () => log('pc:', pc.connectionState);
pc.oniceconnectionstatechange = () => log('ice:', pc.iceConnectionState);

const ws = new WebSocket(cfg.endpoint);
pc.onicecandidate = (e) => {
  if (!e.candidate) return;
  const msg = { senderClientId: CLIENT_ID, action:'ICE_CANDIDATE',
                messagePayload: btoa(JSON.stringify(e.candidate.toJSON())) };
  msg.recipientClientId = masterClientId || '';
  wsSend(msg);
};
function wsSend(obj){ try { ws.send(JSON.stringify(obj)); } catch(err){ log('ws send failed:', String(err)); } }

ws.onopen = async () => {
  log('signaling socket open; sending offer');
  setStatus('negotiating with the vehicle…');
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  wsSend({ senderClientId: CLIENT_ID, action:'SDP_OFFER', recipientClientId: '',
           messagePayload: btoa(JSON.stringify(pc.localDescription)) });
};
ws.onerror = () => { log('signaling socket error'); setStatus('signaling error — see the log'); };
ws.onclose = (e) => log('signaling socket closed', e.code);

ws.onmessage = async (ev) => {
  let msg; try { msg = JSON.parse(ev.data); } catch { return; }
  const type = msg.messageType;
  let payload = null;
  if (msg.messagePayload) { try { payload = JSON.parse(atob(msg.messagePayload)); } catch {} }
  if (type === 'SDP_ANSWER') {
    masterClientId = msg.senderClientId || masterClientId;
    await pc.setRemoteDescription(payload);
    remoteReady = true;
    log('got answer from vehicle; applying', pendingCandidates.length, 'buffered candidate(s)');
    for (const c of pendingCandidates.splice(0)) { try { await pc.addIceCandidate(c); } catch(e){ log('cand err', String(e)); } }
  } else if (type === 'ICE_CANDIDATE' && payload) {
    if (remoteReady) { try { await pc.addIceCandidate(payload); } catch(e){ log('cand err', String(e)); } }
    else pendingCandidates.push(payload);
  } else if (type === 'STATUS_RESPONSE') {
    if (msg.statusResponse && msg.statusResponse.success === 'false')
      log('signaling status error:', JSON.stringify(msg.statusResponse));
  }
};
</script></body></html>
"""


async def serve(config, host="127.0.0.1", port=8723, open_browser=True):
    """Serve the viewer page locally and keep it up until interrupted. Prints browser logs."""
    from aiohttp import web

    page = PAGE.replace("__CONFIG__", json.dumps(config))

    async def index(_request):
        return web.Response(text=page, content_type="text/html")

    async def collect_log(request):
        print(f"   [{time.strftime('%H:%M:%S')}] [browser]", (await request.text()))
        return web.Response(text="ok")

    app = web.Application()
    app.add_routes([web.get("/", index), web.post("/log", collect_log)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    url = f"http://{host}:{port}/"
    print(f"\nViewer at {url}")
    print("Leave this running to keep watching. Press Ctrl-C to stop the viewer.\n")
    if open_browser:
        webbrowser.open(url)
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await runner.cleanup()


# The device id (field 2) is just a label for the viewer device. Testing showed the vehicle accepts
# ANY non-empty string here (our vasPhoneId, a random UUID, even a plain word) once in-vehicle
# consent is granted — it does NOT have to be a registered digital key. The app happens to send its
# CCC key's identityId, but the vehicle doesn't require it. So we use a stable id of our own.
DEFAULT_DEVICE_ID = "rivian-gen2-key-poc"


def device_id_for(key, override=None):
    """The Gear Guard streaming device id for field 2 of start_live_streaming — any stable string.
    Precedence: explicit override, a value stored on the key as `gearguard_device_id`, else a
    constant. It does NOT need to be a registered digital key; the vehicle accepts any string."""
    return override or key.get("gearguard_device_id") or DEFAULT_DEVICE_ID
