--Necessary lib imports 
local nmap = require "nmap"
local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"

--Script metadata and info about the author and purpose of the .nse script
description = [[
Attempts to determine if service is vulnerable to CVE-2022-32073
]]
author = "Michal"
license = "GPL 2.0"
categories = {"vuln"}


--Condition to start the nmap scan on a given port. 
--Rule ssh 
portrule = shortport.ssh

--Action function tests if host is vulnerable for CVE-2022-32073
action = function(host, port) 
  local sock = nmap.new_socket()
  local status = sock:connect(host, port)
  local out = {}
    
  if not status then
    return
  end
  
  status = sock:send("SSH-2.0 Nmap scanner banner!\r\n")
  if not status then
    sock:close()
    return
  end
  
  status, data = sock:receive_buf("\r?\n", false)
  if not status then
    sock:close()
    return
  else
    local version = string.find(data, "wolfSSHD_1.4.7")
    if version ~= nil then
    	--Output formatting and return 
    	table.insert(out, string.format("Host : %s", host.ip))
		table.insert(out, string.format("Hostname : %s", host.name))
		table.insert(out, string.format("Port : %s", port.number))
		table.insert(out, string.format("Service %s detected !", data))
    	table.insert(out, string.format("Host is vulnerable to CVE-2022-32073"))
    else
    	table.insert(out, string.format("Host : %s", host.ip))
		table.insert(out, string.format("Hostname : %s", host.name))
		table.insert(out, string.format("Port : %s", port.number))
    end
  end
  
  return stdnse.format_output(true, out)
end

