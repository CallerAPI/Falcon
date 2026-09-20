-- FreeSWITCH dialplan script. Screen the current session through Falcon.
-- Install under scripts/falcon.lua and call it from the inbound dialplan.
-- Needs mod_curl (`load mod_curl` in modules.conf.xml).

local url = os.getenv("FALCON_URL") or "http://127.0.0.1:8090/v1/screen"
local token = (os.getenv("FALCON_TOKEN") or ""):gsub("%s", "")

local function var(name)
  local v = session:getVariable(name)
  if v == nil or v == "" then
    return nil
  end
  return v
end

local function first(...)
  for i = 1, select("#", ...) do
    local v = select(i, ...)
    if v ~= nil and v ~= "" then
      return v
    end
  end
  return ""
end

-- Falcon reads numbers from sip:, sips:, or tel: URIs. Sofia strips the
-- scheme from sip_from_uri, sip_to_uri, sip_req_uri, and sip_contact_uri.
local function asSIP(v)
  if v == nil or v == "" then
    return ""
  end
  local lower = v:lower()
  if lower:find("<sip:", 1, true) or lower:find("<sips:", 1, true) or lower:find("<tel:", 1, true)
    or lower:find("^%s*sips?:") or lower:find("^%s*tel:") then
    return v
  end
  return "sip:" .. v
end

-- Direction and customer. Set falcon_direction=outbound and
-- falcon_customer=<account id> in the dialplan for calls your own
-- customers place; Falcon then checks the caller id against the numbers
-- you registered for that account.
local payload = {
  switch = "freeswitch",
  direction = var("falcon_direction") or "inbound",
  customer = var("falcon_customer") or "",
  method = var("sip_invite_method") or "INVITE",
  request_uri = asSIP(var("sip_req_uri")),
  source_ip = first(var("sip_network_ip"), var("network_addr")),
  headers = {
    From = asSIP(first(var("sip_full_from"), var("sip_h_From"), var("sip_from_uri"))),
    To = asSIP(first(var("sip_full_to"), var("sip_h_To"), var("sip_to_uri"))),
    ["Call-ID"] = var("sip_call_id") or "",
    ["User-Agent"] = var("sip_user_agent") or "",
    ["P-Asserted-Identity"] = first(var("sip_P-Asserted-Identity"), var("sip_h_P-Asserted-Identity")),
    Identity = var("sip_h_Identity") or "",
    Contact = asSIP(var("sip_contact_uri")),
    Via = var("sip_full_via") or "",
  },
}

-- JSON. FreeSWITCH 1.10 ships freeswitch.JSON. Older builds fall back to
-- a small encoder that escapes what RFC 8259 requires.
local function jsonEscape(s)
  s = tostring(s)
  s = s:gsub('[%c"\\]', function(c)
    if c == '"' then return '\\"' end
    if c == "\\" then return "\\\\" end
    if c == "\n" then return "\\n" end
    if c == "\r" then return "\\r" end
    if c == "\t" then return "\\t" end
    return string.format("\\u%04x", c:byte())
  end)
  return '"' .. s .. '"'
end

local function jsonEncode(t)
  local parts = {}
  for k, v in pairs(t) do
    local val
    if type(v) == "table" then
      val = jsonEncode(v)
    elseif type(v) == "boolean" or type(v) == "number" then
      val = tostring(v)
    else
      val = jsonEscape(v)
    end
    parts[#parts + 1] = jsonEscape(k) .. ":" .. val
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local encoded
if freeswitch.JSON then
  encoded = freeswitch.JSON():encode(payload)
else
  encoded = jsonEncode(payload)
end

-- mod_curl splits its argument on spaces and url-decodes the post body.
-- Percent-encoding the whole body leaves no spaces or quotes to split on
-- and survives that decode exactly.
local function urlencode(s)
  return (s:gsub("[^%w%-%._~]", function(c)
    return string.format("%%%02X", c:byte())
  end))
end

local args = url .. " content-type application/json"
if token ~= "" then
  args = args .. " append_headers X-Falcon-Token:" .. token
end
args = args .. " timeout 2 post " .. urlencode(encoded)

local api = freeswitch.API()
local raw = api:execute("curl", args)

local action = "allow"
local score = "0"
local cause = "CALL_REJECTED"
local sample = false
local seconds = 20
local decoded
if raw and raw ~= "" and freeswitch.JSON then
  local ok, obj = pcall(function() return freeswitch.JSON():decode(raw) end)
  if ok and type(obj) == "table" then
    decoded = obj
  end
end
if decoded and decoded.action then
  action = decoded.action
  score = tostring(decoded.risk_score or 0)
  cause = (decoded.switch_hints or {}).freeswitch_hangup_cause or cause
  sample = decoded.sample == true
  seconds = tonumber((decoded.headers_to_set or {})["X-Falcon-Sample-Seconds"] or "20") or 20
elseif raw and raw:find('"action"') then
  action = raw:match('"action"%s*:%s*"(%w+)"') or "allow"
  score = raw:match('"risk_score"%s*:%s*(%d+)') or "0"
  cause = raw:match('"freeswitch_hangup_cause"%s*:%s*"([%w_]+)"') or cause
  sample = raw:match('"sample"%s*:%s*true') ~= nil
  seconds = tonumber(raw:match('"X%-Falcon%-Sample%-Seconds"%s*:%s*"(%d+)"') or "20") or 20
end

session:setVariable("falcon_action", action)
session:setVariable("falcon_score", score)
session:setVariable("falcon_hangup_cause", cause)
session:setVariable("falcon_call_id", var("sip_call_id") or "")
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
  local path = string.format("%s/%s.wav", dir, var("uuid") or "falcon")
  session:setVariable("RECORD_STEREO", "true")
  session:setVariable("record_sample_rate", "8000")
  session:setVariable("falcon_record_path", path)
  session:execute("record_session", path .. " +" .. tostring(seconds))
end
