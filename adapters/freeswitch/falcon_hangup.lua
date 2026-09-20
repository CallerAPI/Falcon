-- FreeSWITCH hangup hook. Reports how the call ended and, when Falcon asked
-- for a clip, uploads the recording made by falcon.lua.
--
-- Install under scripts/falcon_hangup.lua. falcon.lua sets
--   api_hangup_hook=lua falcon_hangup.lua
-- on every screened session, so nothing else is needed in the dialplan.

local url = os.getenv("FALCON_URL") or "http://127.0.0.1:8090/v1/screen"
local base = url:gsub("/v1/screen$", "")
local token = os.getenv("FALCON_TOKEN") or ""

local call_id = env:getHeader("variable_sip_call_id") or env:getHeader("variable_falcon_call_id") or ""
if call_id == "" then
  return
end

local answered = (env:getHeader("variable_answer_epoch") or "0") ~= "0"
local billsec = tonumber(env:getHeader("variable_billsec") or "0") or 0
local cause = env:getHeader("variable_hangup_cause") or ""

local function shellquote(s)
  return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local auth = token ~= "" and (" -H " .. shellquote("X-Falcon-Token: " .. token)) or ""

local body = string.format('{"call_id":%q,"answered":%s,"duration_s":%d,"hangup_cause":%q}',
  call_id, answered and "true" or "false", billsec, cause)
os.execute("curl -s --max-time 2 -X POST -H 'Content-Type: application/json'" .. auth ..
  " --data-binary " .. shellquote(body) .. " " .. shellquote(base .. "/v1/outcome") .. " >/dev/null 2>&1 &")

-- The clip. falcon.lua started a stereo recording when X-Falcon-Sample was
-- set and stored its path in falcon_record_path.
local path = env:getHeader("variable_falcon_record_path") or ""
if path ~= "" then
  os.execute("(curl -s --max-time 10 -X POST -H 'Content-Type: audio/wav'" .. auth ..
    " --data-binary @" .. shellquote(path) .. " " .. shellquote(base .. "/v1/audio?call_id=" .. call_id) ..
    " >/dev/null 2>&1; rm -f " .. shellquote(path) .. ") &")
end
