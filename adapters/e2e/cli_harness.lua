-- Drive the FreeSWITCH adapter withhold path without a live Falcon.
-- Usage: lua5.4 cli_harness.lua <0|1>
-- 1 means the screen response asks the adapter to hide the caller ID.

local withhold = arg[1] == "1"
local script = (arg[0]:match("(.*/)") or "./") .. "../freeswitch/falcon.lua"

local vars = {
  sip_invite_method = "INVITE",
  sip_req_uri = "+14155550100@carrier.example",
  sip_network_ip = "203.0.113.9",
  sip_full_from = "<sip:+447700900123@203.0.113.9>;tag=1",
  sip_full_to = "<sip:+14155550100@carrier.example>",
  sip_call_id = "cli-harness",
  sip_user_agent = "cli-harness",
  sip_h_Privacy = "none",
  switch_r_sdp = "v=0\r\n",
  uuid = "cli-uuid",
}
local set, executed, hung = {}, {}, nil
_G.session = {
  getVariable = function(_, k) return vars[k] end,
  setVariable = function(_, k, v) set[k] = v end,
  hangup = function(_, cause) hung = cause end,
  execute = function(_, app, data) executed[#executed + 1] = app .. " " .. tostring(data) end,
}
local body = '{"action":"allow","risk_score":15,"headers_to_set":{'
if withhold then
  body = body .. '"X-Falcon-CLI-Withhold":"1"'
end
body = body .. "}}"
_G.freeswitch = {
  consoleLog = function() end,
  API = function()
    return { execute = function() return body end }
  end,
  -- Production FreeSWITCH provides this. decode returns the screen answer.
  JSON = function()
    return {
      encode = function() return "{}" end,
      decode = function(_, s)
        local headers = {}
        if s:find('"X-Falcon-CLI-Withhold":"1"', 1, true) then
          headers["X-Falcon-CLI-Withhold"] = "1"
        end
        return { action = "allow", risk_score = 15, headers_to_set = headers }
      end,
    }
  end,
}
os.getenv = (function(orig)
  return function(k)
    if k == "FALCON_URL" then return "http://127.0.0.1:9/v1/screen" end
    if k == "FALCON_TOKEN" then return "secret" end
    return orig(k)
  end
end)(os.getenv)

dofile(script)

local hid = set["sip_h_Privacy"] == "id"
local ran = false
for _, step in ipairs(executed) do
  if step == "privacy full" then ran = true end
end
local ok = set.falcon_action == "allow" and hung == nil
if withhold then
  ok = ok and hid and ran
else
  ok = ok and not hid and not ran
end
print(string.format("freeswitch withhold=%s privacy=%s ran=%s", tostring(withhold), tostring(set["sip_h_Privacy"]), tostring(ran)))
print("freeswitch cli adapter: " .. (ok and "PASS" or "FAIL"))
os.exit(ok and 0 or 1)
