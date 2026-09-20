-- Drive adapters/freeswitch/falcon.lua the way FreeSWITCH does, against a
-- live Falcon. Provides the freeswitch and session globals the script
-- expects, runs the same curl the switch would, and checks the outcome.
-- Usage: lua5.4 fs_harness.lua <falcon_url> <deny_number> <clean_number>

local url, deny, clean = arg[1], arg[2], arg[3]
local script = (arg[0]:match("(.*/)") or "./") .. "../freeswitch/falcon.lua"

local function shellquote(s)
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

-- FreeSWITCH mod_curl syntax: url [timeout N] [headers '...'] post '...'
local function fs_curl(args)
  local target = args:match("^(%S+)")
  local headers = args:match("headers '(.-)' post")
  local body = args:match("post '(.*)'$")
  body = body:gsub("\\'", "'")
  local cmd = "curl -s --max-time 3 " .. shellquote(target)
  for h in (headers or ""):gmatch("[^,]+") do
    cmd = cmd .. " -H " .. shellquote(h:gsub("^%s*'?", ""):gsub("'?%s*$", ""))
  end
  cmd = cmd .. " --data-binary " .. shellquote(body)
  local p = io.popen(cmd)
  local out = p:read("*a")
  p:close()
  return out
end

local function run(caller, callee)
  local vars = {
    sip_invite_method = "INVITE",
    sip_req_uri = callee .. "@carrier.example",
    network_addr = "203.0.113.9",
    sip_from_uri = caller .. "@203.0.113.9",
    sip_to_uri = callee .. "@carrier.example",
    sip_call_id = "fs-e2e-" .. caller .. "@203.0.113.9",
    sip_user_agent = "e2e-harness/1.0",
    sip_contact_uri = caller .. "@203.0.113.9",
  }
  local set, hung = {}, nil
  _G.session = {
    getVariable = function(_, k) return vars[k] end,
    setVariable = function(_, k, v) set[k] = v end,
    hangup = function(_, cause) hung = cause end,
  }
  _G.freeswitch = { API = function() return { execute = function(_, name, args) assert(name == "curl"); return fs_curl(args) end } end }
  _G.cjson = nil
  os.getenv = (function(orig) return function(k) if k == "FALCON_URL" then return url end return orig(k) end end)(os.getenv)
  dofile(script)
  return set, hung
end

local d, dh = run(deny, "+14155550100")
local a, ah = run(clean, "+14155550100")
print(string.format("denied: action=%s score=%s hangup=%s", d.falcon_action, d.falcon_score, tostring(dh)))
print(string.format("allowed: action=%s score=%s hangup=%s", a.falcon_action, a.falcon_score, tostring(ah)))
local ok = d.falcon_action == "reject" and dh ~= nil and a.falcon_action == "allow" and ah == nil
  and d["sip_h_X-Falcon-Action"] == "reject" and a["sip_h_X-Falcon-Action"] == "allow"
print("freeswitch lua adapter: " .. (ok and "PASS" or "FAIL"))
os.exit(ok and 0 or 1)
