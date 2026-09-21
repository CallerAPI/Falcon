-- Drive adapters/freeswitch/falcon.lua the way FreeSWITCH does, against a
-- live Falcon. Provides the freeswitch and session globals the script
-- expects, parses the mod_curl argument string with the same rules as
-- mod_curl.c, runs the request with curl, and checks the outcome.
-- Usage: lua5.4 fs_harness.lua <falcon_url> <deny_number> <clean_number>

local url, deny, clean = arg[1], arg[2], arg[3]
local script = (arg[0]:match("(.*/)") or "./") .. "../freeswitch/falcon.lua"

local function shellquote(s)
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

-- switch_separate_string(buf, ' ', ...): split on spaces, a single quote
-- toggles quoting, a backslash escapes the next character, quotes and
-- escapes are stripped from each token.
local function separate(s)
  local out, cur, quoted, i = {}, "", false, 1
  while i <= #s do
    local c = s:sub(i, i)
    if c == "\\" and i < #s then
      cur = cur .. s:sub(i + 1, i + 1)
      i = i + 1
    elseif c == "'" then
      quoted = not quoted
    elseif c == " " and not quoted then
      if cur ~= "" then out[#out + 1] = cur end
      cur = ""
    else
      cur = cur .. c
    end
    i = i + 1
  end
  if cur ~= "" then out[#out + 1] = cur end
  return out
end

-- switch_url_decode: %XX only. A plus sign is left alone.
local function urldecode(s)
  return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

-- mod_curl curl_function: url first, then keywords in any order.
local function fs_curl(args)
  local argv = separate(args)
  local target = argv[1]
  local method, postdata, content_type, timeout = "get", "", nil, nil
  local append = {}
  local i = 2
  while i <= #argv do
    local a = argv[i]:lower()
    if a == "headers" or a == "json" or a == "insecure" or a == "secure" then
      -- output flags, no argument
    elseif a == "get" or a == "head" then
      method = a
    elseif a == "post" or a == "put" or a == "patch" or a == "delete" then
      method = a
      i = i + 1
      postdata = urldecode(argv[i] or "")
    elseif a == "content-type" then
      i = i + 1
      content_type = argv[i]
    elseif a == "append_headers" then
      i = i + 1
      append[#append + 1] = argv[i]
    elseif a == "timeout" or a == "connect-timeout" then
      i = i + 1
      timeout = tonumber((argv[i] or ""):match("^%d+")) or timeout
    elseif a == "proxy" then
      i = i + 1
    else
      error("mod_curl would ignore unknown token: " .. argv[i])
    end
    i = i + 1
  end
  assert(method == "post", "falcon.lua must POST, got " .. method)
  assert(content_type == "application/json", "content-type must be application/json, got " .. tostring(content_type))
  assert(timeout and timeout > 0, "timeout must be set")
  local cmd = "curl -s --max-time " .. tostring(timeout) .. " -X POST " .. shellquote(target)
  cmd = cmd .. " -H " .. shellquote("Content-Type: " .. content_type)
  for _, h in ipairs(append) do
    cmd = cmd .. " -H " .. shellquote(h)
  end
  cmd = cmd .. " --data-binary " .. shellquote(postdata)
  local p = io.popen(cmd)
  local out = p:read("*a")
  p:close()
  return out, postdata
end

local lastBody
local function run(caller, callee)
  local vars = {
    sip_invite_method = "INVITE",
    sip_req_uri = callee .. "@carrier.example",
    sip_network_ip = "203.0.113.9",
    network_addr = "203.0.113.9",
    -- Display name with quotes: the encoder must escape it.
    sip_full_from = '"Alice \\"A\\" Smith" <sip:' .. caller .. "@203.0.113.9>;tag=1",
    sip_from_uri = caller .. "@203.0.113.9",
    sip_full_to = "<sip:" .. callee .. "@carrier.example>",
    sip_to_uri = callee .. "@carrier.example",
    sip_call_id = "fs-e2e-" .. caller .. "@203.0.113.9",
    sip_user_agent = "e2e-harness/1.0 (space and 100% plain)",
    sip_contact_uri = caller .. "@203.0.113.9",
    sip_full_via = "SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKe2e",
    uuid = "e2e-uuid",
  }
  local set, hung = {}, nil
  _G.session = {
    getVariable = function(_, k) return vars[k] end,
    setVariable = function(_, k, v) set[k] = v end,
    hangup = function(_, cause) hung = cause end,
    execute = function() end,
  }
  _G.freeswitch = {
    consoleLog = function(level, msg) io.stderr:write("[" .. level .. "] " .. msg) end,
    API = function()
      return { execute = function(_, name, args)
        assert(name == "curl", "api:execute must call curl")
        local out, body = fs_curl(args)
        lastBody = body
        return out
      end }
    end,
    JSON = nil,
  }
  os.getenv = (function(orig) return function(k)
    if k == "FALCON_URL" then return url end
    if k == "FALCON_TOKEN" then return "e2e-token" end
    return orig(k)
  end end)(os.getenv)
  dofile(script)
  return set, hung
end

local d, dh = run(deny, "+14155550100")
local a, ah = run(clean, "+14155550100")
print(string.format("denied: action=%s score=%s hangup=%s", d.falcon_action, d.falcon_score, tostring(dh)))
print(string.format("allowed: action=%s score=%s hangup=%s", a.falcon_action, a.falcon_score, tostring(ah)))
print("body: " .. tostring(lastBody))
local ok = d.falcon_action == "reject" and dh ~= nil and a.falcon_action == "allow" and ah == nil
  and d["sip_h_X-Falcon-Action"] == "reject" and a["sip_h_X-Falcon-Action"] == "allow"
  and lastBody:find('"From":"\\"Alice \\\\\\"A\\\\\\" Smith\\" <sip:', 1, true) ~= nil
  and lastBody:find("100% plain", 1, true) ~= nil
print("freeswitch lua adapter: " .. (ok and "PASS" or "FAIL"))
os.exit(ok and 0 or 1)
