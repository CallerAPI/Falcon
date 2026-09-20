-- FreeSWITCH dialplan script. Screen the current session through Falcon.
-- Install under scripts/falcon.lua and call it from the inbound dialplan.

local url = os.getenv("FALCON_URL") or "http://127.0.0.1:8090/v1/screen"
local token = os.getenv("FALCON_TOKEN") or ""

local function hdr(name)
  return session:getVariable("sip_h_" .. name) or ""
end

-- Direction and customer. Set falcon_direction=outbound and
-- falcon_customer=<account id> in the dialplan for calls your own
-- customers place; Falcon then checks the caller id against the numbers
-- you registered for that account.
local direction = session:getVariable("falcon_direction") or "inbound"
local customer = session:getVariable("falcon_customer") or ""

local payload = {
  switch = "freeswitch",
  direction = direction,
  customer = customer,
  method = session:getVariable("sip_invite_method") or "INVITE",
  request_uri = session:getVariable("sip_req_uri") or "",
  source_ip = session:getVariable("network_addr") or "",
  headers = {
    From = hdr("From") ~= "" and hdr("From") or (session:getVariable("sip_from_uri") or ""),
    To = hdr("To") ~= "" and hdr("To") or (session:getVariable("sip_to_uri") or ""),
    ["Call-ID"] = session:getVariable("sip_call_id") or "",
    ["User-Agent"] = session:getVariable("sip_user_agent") or "",
    ["P-Asserted-Identity"] = hdr("P-Asserted-Identity"),
    Identity = hdr("Identity"),
    Contact = session:getVariable("sip_contact_uri") or "",
    ["Max-Forwards"] = hdr("Max-Forwards"),
  },
}

local api = freeswitch.API()
local body = payload
-- Use cJSON if present, else a minimal encoder for this payload.
local encoded
if (cjson and cjson.encode) then
  encoded = cjson.encode(body)
else
  encoded = string.format(
    '{"switch":"freeswitch","direction":"%s","customer":"%s","method":"%s","request_uri":"%s","source_ip":"%s","headers":{"From":"%s","To":"%s","Call-ID":"%s","User-Agent":"%s","P-Asserted-Identity":"%s","Identity":"%s","Contact":"%s"}}',
    body.direction, body.customer, body.method, body.request_uri, body.source_ip,
    body.headers.From, body.headers.To, body.headers["Call-ID"],
    body.headers["User-Agent"], body.headers["P-Asserted-Identity"],
    body.headers.Identity, body.headers.Contact
  )
end

-- mod_curl args start with the URL. The command name is the first
-- argument to api:execute, not part of this string.
local curl = string.format(
  "%s timeout 2s headers 'Content-Type: application/json%s' post '%s'",
  url,
  token ~= "" and ("','X-Falcon-Token: " .. token) or "",
  encoded:gsub("'", "\\'")
)
local raw = api:execute("curl", curl)
local action = "allow"
local score = "0"
local cause = "CALL_REJECTED"
local sample = false
local seconds = 20
if raw and raw:find("action") then
  action = raw:match('"action"%s*:%s*"(%w+)"') or "allow"
  score = raw:match('"risk_score"%s*:%s*(%d+)') or "0"
  cause = raw:match('"freeswitch_hangup_cause"%s*:%s*"([%w_]+)"') or cause
  sample = raw:match('"sample"%s*:%s*true') ~= nil
  seconds = tonumber(raw:match('"X%-Falcon%-Sample%-Seconds"%s*:%s*"(%d+)"') or "20") or 20
end

session:setVariable("falcon_action", action)
session:setVariable("falcon_score", score)
session:setVariable("falcon_hangup_cause", cause)
session:setVariable("falcon_call_id", session:getVariable("sip_call_id") or "")
session:setVariable("sip_h_X-Falcon-Action", action)
session:setVariable("sip_h_X-Falcon-Score", score)
-- Report the outcome at hangup, and the clip when one was taken.
session:setVariable("api_hangup_hook", "lua falcon_hangup.lua")

if action == "reject" or action == "challenge" then
  session:hangup(cause)
  return
end

-- Falcon asked for the first seconds of audio: record both legs to
-- separate channels so caller and callee can be told apart, stop after
-- the requested length, and let the hangup hook upload it.
if sample then
  local dir = os.getenv("FALCON_RECORD_DIR") or "/tmp/falcon"
  os.execute("mkdir -p " .. dir)
  local path = string.format("%s/%s.wav", dir, session:getVariable("uuid"))
  session:setVariable("RECORD_STEREO", "true")
  session:setVariable("record_sample_rate", "8000")
  session:setVariable("falcon_record_path", path)
  session:execute("record_session", path .. " +" .. tostring(seconds))
end
