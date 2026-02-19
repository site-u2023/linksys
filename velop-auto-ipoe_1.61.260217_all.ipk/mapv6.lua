-------------------------------------------------------------------------------------------------
--      Linksys Auto IPoE module for NTT IPv4 over IPv6 environment
-------------------------------------------------------------------------------------------------
-- This script contains proprietary and confidential information.
-- Unauthorized copying, distribution, modification, or use of this code is strictly prohibited.
-- Legal actions will be taken against any infringement of intellectual property rights.

local ubus = require "ubus"
local openssl = require("openssl")

-------------------------------------------------------------------------------------------------
--      System utility functions
-------------------------------------------------------------------------------------------------
local sys = {}

-- Execute a command and return stdout (like luci.sys.exec)
function sys.exec(command)
    local handle = io.popen(command, "r")
    if not handle then return "" end
    local result = handle:read("*a")
    handle:close()
    return result or ""
end

-- Execute a command and return exit code (like luci.sys.call)
function sys.call(command)
    local ret = os.execute(command)
    -- Lua 5.1 returns exit code directly, Lua 5.2+ returns true/nil, exit code
    if type(ret) == "boolean" then
        return ret and 0 or 1
    elseif type(ret) == "number" then
        -- Lua 5.1: os.execute returns exit code * 256 on some systems
        if ret > 255 then
            return math.floor(ret / 256)
        end
        return ret
    end
    return 1
end


local cjson = require("cjson.safe")
local json = {
    parse = function(str)
        if not str or str == "" then return nil end
        return cjson.decode(str)
    end,
    stringify = function(obj, pretty)
        if not obj then return nil end
        if pretty then
            -- cjson.safe doesn't have pretty print, just encode normally
            return cjson.encode(obj)
        end
        return cjson.encode(obj)
    end
}


-------------------------------------------------------------------------------------------------
--      UCI wrapper
-------------------------------------------------------------------------------------------------
local uci_lib = require("uci")

local function uci_cursor()
    local ctx = uci_lib.cursor()
    local obj = {}
    
    -- Get a config value
    function obj:get(config, section, option)
        if option then
            return ctx:get(config, section, option)
        else
            return ctx:get(config, section)
        end
    end
    
    -- Set a config value
    function obj:set(config, section, option, value)
        if value ~= nil then
            return ctx:set(config, section, option, value)
        else
            -- When called with 3 args, option is actually the value (section type)
            return ctx:set(config, section, option)
        end
    end
    
    -- Delete a config option or section
    function obj:delete(config, section, option)
        if option then
            return ctx:delete(config, section, option)
        else
            return ctx:delete(config, section)
        end
    end
    
    -- Commit changes to a config
    function obj:commit(config)
        return ctx:commit(config)
    end
    
    -- Set a list value
    function obj:set_list(config, section, option, list)
        return ctx:set(config, section, option, list)
    end
    
    -- Get a list value
    function obj:get_list(config, section, option)
        local val = ctx:get(config, section, option)
        if type(val) == "table" then
            return val
        elseif val then
            return { val }
        else
            return {}
        end
    end
    
    -- Iterate over sections (foreach)
    function obj:foreach(config, stype, callback)
        return ctx:foreach(config, stype, callback)
    end
    
    -- Add a new anonymous section
    function obj:add(config, stype)
        return ctx:add(config, stype)
    end
    
    -- Revert changes
    function obj:revert(config)
        return ctx:revert(config)
    end
    
    -- uci:section(config, stype, name, options)
    function obj:section(config, stype, name, options)
        -- First, set the section type (creates section if it doesn't exist)
        ctx:set(config, name, stype)
        -- Then set all the options
        if options and type(options) == "table" then
            for key, value in pairs(options) do
                ctx:set(config, name, key, value)
            end
        end
        return name
    end
    
    return obj
end

local uci = uci_cursor()




-------------------------------------------------------------------------------------------------
--      Independent IP utility functions
-------------------------------------------------------------------------------------------------
local ip_util = {}

-- Parse IPv6 address string into 8 x 16-bit sections
local function parse_ipv6_sections(addr_str)
    if not addr_str or addr_str == "" then return nil end
    -- Remove prefix length if present
    addr_str = addr_str:match("^([^/]+)")
    if not addr_str then return nil end
    
    local sections = {}
    local double_colon_pos = nil
    local parts_before = {}
    local parts_after = {}
    
    -- Check for :: (compressed zeros)
    local before, after = addr_str:match("^(.*)::(.*)$")
    if before then
        -- Split before ::
        if before ~= "" then
            for part in before:gmatch("[^:]+") do
                table.insert(parts_before, tonumber(part, 16) or 0)
            end
        end
        -- Split after ::
        if after ~= "" then
            for part in after:gmatch("[^:]+") do
                table.insert(parts_after, tonumber(part, 16) or 0)
            end
        end
        -- Fill with zeros
        local zeros_needed = 8 - #parts_before - #parts_after
        for _, v in ipairs(parts_before) do
            table.insert(sections, v)
        end
        for _ = 1, zeros_needed do
            table.insert(sections, 0)
        end
        for _, v in ipairs(parts_after) do
            table.insert(sections, v)
        end
    else
        -- No :: compression
        for part in addr_str:gmatch("[^:]+") do
            table.insert(sections, tonumber(part, 16) or 0)
        end
    end
    
    if #sections ~= 8 then return nil end
    return sections
end

-- Convert 8 sections back to IPv6 string (compressed format)
local function sections_to_ipv6_string(sections, prefix_len)
    if not sections or #sections ~= 8 then return nil end
    
    -- Find longest run of zeros for compression
    local best_start, best_len = -1, 0
    local cur_start, cur_len = -1, 0
    
    for i = 1, 8 do
        if sections[i] == 0 then
            if cur_start == -1 then
                cur_start = i
                cur_len = 1
            else
                cur_len = cur_len + 1
            end
        else
            if cur_len > best_len then
                best_start = cur_start
                best_len = cur_len
            end
            cur_start = -1
            cur_len = 0
        end
    end
    if cur_len > best_len then
        best_start = cur_start
        best_len = cur_len
    end
    
    -- Build string
    local result = {}
    local i = 1
    while i <= 8 do
        if best_len >= 2 and i == best_start then
            if i == 1 then
                table.insert(result, "")
            end
            table.insert(result, "")
            i = i + best_len
            if i > 8 then
                table.insert(result, "")
            end
        else
            table.insert(result, string.format("%x", sections[i]))
            i = i + 1
        end
    end
    
    local addr_str = table.concat(result, ":")
    if prefix_len then
        return addr_str .. "/" .. prefix_len
    end
    return addr_str
end

-- Apply prefix mask to IPv6 sections
local function apply_ipv6_prefix_mask(sections, prefix_len)
    if not sections or #sections ~= 8 then return nil end
    local masked = {}
    local bits_remaining = prefix_len
    
    for i = 1, 8 do
        if bits_remaining >= 16 then
            masked[i] = sections[i]
            bits_remaining = bits_remaining - 16
        elseif bits_remaining > 0 then
            local mask = bit32 and bit32.lshift(0xFFFF, 16 - bits_remaining) or
                         (0xFFFF - (2^(16 - bits_remaining) - 1))
            mask = mask % 0x10000
            masked[i] = (sections[i] or 0) % 0x10000
            masked[i] = masked[i] - (masked[i] % (2^(16 - bits_remaining)))
            bits_remaining = 0
        else
            masked[i] = 0
        end
    end
    return masked
end

-- IPv6 object constructor
function ip_util.IPv6(addr_str, prefix_len)
    if not addr_str then return nil end
    
    -- Extract prefix length from address if not provided separately
    local addr_only, addr_prefix = addr_str:match("^([^/]+)/(%d+)$")
    if addr_only then
        addr_str = addr_only
        prefix_len = prefix_len or tonumber(addr_prefix)
    end
    prefix_len = prefix_len or 128
    
    local sections = parse_ipv6_sections(addr_str)
    if not sections then return nil end
    
    local obj = {
        _sections = sections,
        _prefix = prefix_len
    }
    
    -- Get string representation
    function obj:string()
        return sections_to_ipv6_string(self._sections, self._prefix < 128 and self._prefix or nil)
    end
    
    -- Get network address with specified prefix
    function obj:network(new_prefix)
        new_prefix = new_prefix or self._prefix
        local masked = apply_ipv6_prefix_mask(self._sections, new_prefix)
        if not masked then return nil end
        
        local net_obj = {
            _sections = masked,
            _prefix = new_prefix
        }
        net_obj.string = obj.string
        net_obj.network = obj.network
        net_obj.contains = obj.contains
        return net_obj
    end
    
    -- Check if this network contains another address
    function obj:contains(other)
        if not other or not other._sections then return false end
        local my_net = apply_ipv6_prefix_mask(self._sections, self._prefix)
        local other_net = apply_ipv6_prefix_mask(other._sections, self._prefix)
        if not my_net or not other_net then return false end
        
        for i = 1, 8 do
            if my_net[i] ~= other_net[i] then
                return false
            end
        end
        return true
    end
    
    return obj
end

-- Parse IPv4 address string into 4 octets
local function parse_ipv4_octets(addr_str)
    if not addr_str or addr_str == "" then return nil end
    -- Remove prefix length if present
    local addr_only = addr_str:match("^([^/]+)")
    if not addr_only then return nil end
    
    local octets = {}
    for octet in addr_only:gmatch("(%d+)") do
        local num = tonumber(octet)
        if not num or num < 0 or num > 255 then return nil end
        table.insert(octets, num)
    end
    
    if #octets ~= 4 then return nil end
    return octets
end

-- Convert netmask to prefix length
local function netmask_to_prefix(netmask)
    local octets = parse_ipv4_octets(netmask)
    if not octets then return 32 end
    
    local prefix = 0
    for _, octet in ipairs(octets) do
        while octet > 0 do
            if octet >= 128 then
                prefix = prefix + 1
                octet = (octet - 128) * 2
            else
                break
            end
        end
    end
    return prefix
end

-- Convert prefix length to netmask octets
local function prefix_to_netmask_octets(prefix)
    local octets = {0, 0, 0, 0}
    for i = 1, 4 do
        if prefix >= 8 then
            octets[i] = 255
            prefix = prefix - 8
        elseif prefix > 0 then
            octets[i] = 256 - (2 ^ (8 - prefix))
            prefix = 0
        else
            octets[i] = 0
        end
    end
    return octets
end

-- Apply prefix mask to IPv4 octets
local function apply_ipv4_prefix_mask(octets, prefix_len)
    if not octets or #octets ~= 4 then return nil end
    local mask_octets = prefix_to_netmask_octets(prefix_len)
    local masked = {}
    for i = 1, 4 do
        -- Bitwise AND using modular arithmetic
        masked[i] = math.floor(octets[i] / 1) % 256
        local mask = mask_octets[i]
        -- Manual bitwise AND
        local result = 0
        local bit_val = 128
        for _ = 1, 8 do
            if octets[i] >= bit_val and mask >= bit_val then
                result = result + bit_val
            end
            if octets[i] >= bit_val then octets[i] = octets[i] - bit_val end
            if mask >= bit_val then mask = mask - bit_val end
            bit_val = bit_val / 2
        end
        masked[i] = result
    end
    return masked
end

-- IPv4 object constructor
function ip_util.IPv4(addr_str, netmask)
    if not addr_str then return nil end
    
    local prefix_len
    local addr_only
    
    -- Check if addr_str contains CIDR notation
    local addr_part, cidr = addr_str:match("^([^/]+)/(%d+)$")
    if addr_part then
        addr_only = addr_part
        prefix_len = tonumber(cidr)
    else
        addr_only = addr_str
    end
    
    -- If netmask is provided as second argument
    if netmask and type(netmask) == "string" then
        prefix_len = netmask_to_prefix(netmask)
    elseif netmask and type(netmask) == "number" then
        prefix_len = netmask
    end
    
    prefix_len = prefix_len or 32
    
    local octets = parse_ipv4_octets(addr_only)
    if not octets then return nil end
    
    local obj = {
        _octets = octets,
        _prefix = prefix_len
    }
    
    -- Get string representation with CIDR
    function obj:string()
        local addr = table.concat(self._octets, ".")
        if self._prefix < 32 then
            return addr .. "/" .. self._prefix
        end
        return addr
    end
    
    -- Get host address (without CIDR prefix)
    function obj:host()
        local host_obj = {
            _octets = self._octets,
            _prefix = 32
        }
        function host_obj:string()
            return table.concat(self._octets, ".")
        end
        return host_obj
    end
    
    -- Get network address with specified prefix
    function obj:network(new_prefix)
        new_prefix = new_prefix or self._prefix
        local masked = apply_ipv4_prefix_mask({self._octets[1], self._octets[2], self._octets[3], self._octets[4]}, new_prefix)
        if not masked then return nil end
        
        local net_obj = {
            _octets = masked,
            _prefix = new_prefix
        }
        net_obj.string = obj.string
        net_obj.host = obj.host
        net_obj.network = obj.network
        net_obj.contains = obj.contains
        return net_obj
    end
    
    -- Check if this network contains another address
    function obj:contains(other)
        if not other or not other._octets then return false end
        local my_net = apply_ipv4_prefix_mask({self._octets[1], self._octets[2], self._octets[3], self._octets[4]}, self._prefix)
        local other_net = apply_ipv4_prefix_mask({other._octets[1], other._octets[2], other._octets[3], other._octets[4]}, self._prefix)
        if not my_net or not other_net then return false end
        
        for i = 1, 4 do
            if my_net[i] ~= other_net[i] then
                return false
            end
        end
        return true
    end
    
    return obj
end

-- Alias for compatibility
local ip = ip_util


-- For flag management --
local init_execute = 0
local change_execute = 0
local under_router = 0 -- 0: not under router, 1: under router, 2: under HGW, 3: under HGW but CE can handle map-e/ds-lite
local debug_nohgw = 0
local qsdk = tonumber(uci:get("ca_setup", "getmap", "qsdk")) or 12.5


-- Get command line arguments
local args = {...}


-- Log file paths
local temp_log_file = "/tmp/ipoe_log.txt"
local final_log_file = "/etc/ipoe.log"
local last_log_file = "/etc/ipoe_last.log"


-- Script path for cron & Startup registration --
local script_path = "/usr/lib/lua/mapv6.lua"
local rcLocalPath = "/etc/rc.local"

-- Sysctl drop-in used by tune_sysctl()
local sysctl_config = "/etc/sysctl.d/99-auto-ipoe.conf"
local dscp_zero_nft_dir = "/usr/share/nftables.d/chain-post/mangle_postrouting"
local dscp_zero_nft_file = dscp_zero_nft_dir .. "/90-dscp-zero.nft"
local dscp_zero_fw_user_file = "/etc/firewall.user"
local dscp_zero_fw_user_marker = "DSCP --set-dscp 0"
local quic_block_rule_section = "block_quic_ipoe"


-- Shellquote function to safely quote strings
local function shellquote(str)
    if not str then return "''" end
    return "'" .. string.gsub(str, "'", "'\\''") .. "'"
end

-- ca_setup.map.debug: "1" => skip certificate verification (-k), "0"/unset => verify
local function should_skip_cert_verification()
    return tostring(uci:get("ca_setup", "map", "debug") or "0") == "1"
end

local function get_pid()
    local f = io.open("/proc/self/stat", "r")
    if f then
        local pid = f:read("*n")
        f:close()
        if pid and pid > 0 then
            return pid
        end
    end
    local handle = io.popen("echo $$")
    local pid = handle:read("*n")
    handle:close()
    return pid
end


-- URL-encode a string for safe query construction
local function urlencode(str)
    if not str then return "" end
    return (str:gsub("([^%w%-_%.~])", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end


-- log_message function to log and print messages simultaneously
local function log_message(message)
    message = tostring(message or "")
    os.execute("logger " .. shellquote("IPOE: " .. message))
    print(message)
    local file = io.open(temp_log_file, "a")
    if file then
        file:write(message .. "\n")
        file:close()
    else
        print("Failed to write to temporary log file: " .. temp_log_file)
    end
end

local function ensure_dscp_zero_firewall_user()
    local content = ""
    local existing = io.open(dscp_zero_fw_user_file, "r")
    if existing then
        content = existing:read("*a") or ""
        existing:close()
    end

    if content:find(dscp_zero_fw_user_marker, 1, true) then
        return false
    end

    local out = io.open(dscp_zero_fw_user_file, "a")
    if not out then
        log_message("Failed to create DSCP reset commands: " .. dscp_zero_fw_user_file)
        return false
    end

    if content ~= "" and not content:match("\n$") then
        out:write("\n")
    end

    out:write([[# Reset DSCP to 0
iptables  -t mangle -C POSTROUTING -j DSCP --set-dscp 0 2>/dev/null || \
iptables  -t mangle -A POSTROUTING -j DSCP --set-dscp 0
ip6tables -t mangle -C POSTROUTING -j DSCP --set-dscp 0 2>/dev/null || \
ip6tables -t mangle -A POSTROUTING -j DSCP --set-dscp 0
]])
    out:close()
    log_message("Installed DSCP reset commands: " .. dscp_zero_fw_user_file)
    return true
end

local function ensure_dscp_zero_nft()
    if qsdk == 12.2 then
        return ensure_dscp_zero_firewall_user()
    end

    if not dscp_zero_nft_file or dscp_zero_nft_file == "" then
        return false
    end

    local existing = io.open(dscp_zero_nft_file, "r")
    if existing then
        existing:close()
        return false
    end

    sys.call("mkdir -p " .. shellquote(dscp_zero_nft_dir) .. " >/dev/null 2>&1")
    local out = io.open(dscp_zero_nft_file, "w")
    if not out then
        log_message("Failed to create DSCP reset include: " .. dscp_zero_nft_file)
        return false
    end

    out:write([[oifname { "eth0", "map-wanmap" } ip dscp set cs0 comment "!custom: reset DSCP v4"
oifname { "eth0", "map-wanmap" } ip6 dscp set cs0 comment "!custom: reset DSCP v6"
]])
    out:close()
    log_message("Installed DSCP reset include: " .. dscp_zero_nft_file)
    return true
end

local function remove_dscp_zero_nft()
    if not dscp_zero_nft_file or dscp_zero_nft_file == "" then
        return false
    end

    local f = io.open(dscp_zero_nft_file, "r")
    if not f then
        return false
    end
    f:close()

    local ok, err = os.remove(dscp_zero_nft_file)
    if ok then
        log_message("Removed DSCP reset include: " .. dscp_zero_nft_file)
        return true
    end

    log_message("Failed to remove DSCP reset include: " .. dscp_zero_nft_file .. " (" .. tostring(err) .. ")")
    return false
end

local function ensure_quic_block_firewall_rule()
    uci:section("firewall", "rule", quic_block_rule_section, {
        name = "Block-QUIC-IPoE",
        proto = "udp",
        dest_port = "443",
        src = "lan",
        dest = "wan",
        target = "DROP",
        family = "ipv4",
        enabled = "1"
    })
end

local function remove_quic_block_firewall_rule()
    if not uci:get("firewall", quic_block_rule_section) then
        return false
    end

    uci:delete("firewall", quic_block_rule_section)
    log_message("Removed firewall rule: " .. quic_block_rule_section)
    return true
end

-- Interface up/down helpers with QSDK-aware fallback
local function interface_action(action, iface)
    if not iface or iface == "" then
        log_message("Interface action skipped: missing interface")
        return false
    end
    if not iface:match("^[%w%.%-%_]+$") then
        log_message("Interface action skipped: invalid interface name " .. tostring(iface))
        return false
    end

    local use_ubus = (qsdk and qsdk >= 12.5)
    local ubus_cmd = string.format("ubus call network.interface.%s %s", iface, action)
    local if_cmd = (action == "up") and ("ifup " .. iface) or ("ifdown " .. iface)
    local primary_cmd = use_ubus and ubus_cmd or if_cmd
    local fallback_cmd = use_ubus and if_cmd or ubus_cmd

    local rc = sys.call(primary_cmd .. " >/dev/null 2>&1")
    if rc == 0 then
        return true
    end
    log_message("Interface " .. action .. " failed via " .. (use_ubus and "ubus" or "ifupdown") ..
        " for " .. iface .. " (rc=" .. tostring(rc) .. "), trying fallback")
    local rc2 = sys.call(fallback_cmd .. " >/dev/null 2>&1")
    if rc2 == 0 then
        return true
    end
    log_message("Interface " .. action .. " failed via fallback for " .. iface .. " (rc=" .. tostring(rc2) .. ")")
    return false
end

local function interface_up(iface)
    return interface_action("up", iface)
end

local function interface_down(iface)
    return interface_action("down", iface)
end

-- Reboot wrapper for QSDK variants
local function reboot_system()
    if qsdk and qsdk >= 12.5 then
        os.execute("ubus call system reboot")
    else
        os.execute("reboot")
    end
end


-- Append temporary logs to persistent storage at the end of the program
local function save_logs_to_persistent_storage()
    log_message("### end of logging ###")
    local file = io.open(temp_log_file, "r")
    if file then
        local logs = file:read("*a")
        file:close()

        -- Read existing logs
        local existing_logs = ""
        local final_file = io.open(final_log_file, "r")
        if final_file then
            existing_logs = final_file:read("*a")
            final_file:close()
        end

        -- Insert new logs at the beginning
        local new_logs = logs .. existing_logs

        -- Limit the number of lines (maximum 1000 lines)
        local log_lines = {}
        for line in new_logs:gmatch("[^\r\n]+") do
            table.insert(log_lines, line)
        end

        if #log_lines > 1000 then
            log_lines = {unpack(log_lines, 1, 1000)}
        end

        -- Save to main log file
        final_file = io.open(final_log_file, "w")
        if final_file then
            final_file:write(table.concat(log_lines, "\n"))
            final_file:close()
        else
            print("Failed to write to final log file: " .. final_log_file)
        end

        -- Save a copy to the last log file (complete overwrite)
        local last_file = io.open(last_log_file, "w")
        if last_file then
            last_file:write(logs)
            last_file:close()
            print("Saved copy of current log to " .. last_log_file)
        else
            print("Failed to write to last log file: " .. last_log_file)
            
        end

        os.remove(temp_log_file)
    else
        print("No temporary logs found to save.")
    end
    os.remove("/tmp/ipoe_pending")
end


-- Remove temporary logs at the end of the program
local function discard_temp_logs()
    local file = io.open(temp_log_file, "r")
    if file then
        file:close()
        os.remove(temp_log_file)
        print("Temporary logs discarded.")
    else
        print("No temporary logs found to discard.")
    end
    os.remove("/tmp/ipoe_pending")
end


-- Function to check if the log file is empty
local function dupe_exec_check()
    local f = io.open(temp_log_file, "r")
    if not f then return true end
    local size = f:seek("end")
    f:close()
    return size == 0
end


-- Enable script lock to prevent duplicate execution of mapv6
local function script_lock_enable()
    local lock_file = '/tmp/mapv6_script_lock'
    local restart_flag_file = '/tmp/mapv6_network_restart_flag'
    
    -- Check if lock file exists
    if sys.call('test -f ' .. lock_file) == 0 then
        -- File exists, check if process is still running
        local f = io.open(lock_file, "r")
        if f then
            local pid = f:read("*n")
            f:close()
            
            -- Check if process with this PID still exists
            if pid and pid > 0 then
                -- Test if process exists using kill -0
                local process_exists = os.execute('kill -0 ' .. pid .. ' 2>/dev/null') == 0
                if process_exists then
                    log_message("Another instance (PID: " .. pid .. ") is already running. Exiting.")
                    save_logs_to_persistent_storage()
                    os.exit()
                else
                    log_message("Stale lock file found. Previous process (PID: " .. pid .. ") is no longer running.")
                    -- Continue and create a new lock file
                end
            end
        end
    end
    
    -- Create lock file with current PID
    local pid = get_pid()
    local f = io.open(lock_file, "w")
    if f then
        f:write(pid)
        f:close()
        log_message("Created lock file with PID: " .. pid)
    else
        log_message("Failed to create lock file. Check permissions or disk space.")
    end
    
    -- Create network restart flag file
    os.execute('touch ' .. restart_flag_file)
    log_message("Created network restart flag file to prevent duplicate execution")
end


-- Disable script lock to prevent duplicate execution of mapv6
local function script_lock_disable()
    local lock_file = '/tmp/mapv6_script_lock'
    local restart_flag_file = '/tmp/mapv6_network_restart_flag'
    
    -- Check if lock file exists
    if sys.call('test -f ' .. lock_file) ~= 0 then
        log_message("No lock file found to remove")
        return
    end
    
    -- Read the PID from lock file
    local f = io.open(lock_file, "r")
    if not f then
        log_message("Lock file exists but couldn't be read, removing it")
        os.execute('rm -f ' .. lock_file)
        os.execute('touch /tmp/hotplug_initialized')
        return
    end
    
    local saved_pid_str = f:read("*a")
    f:close()
    
    -- Get current process PID more reliably
    local current_pid = get_pid()
    
    log_message("Lock file PID: " .. (saved_pid_str or "nil") .. ", Current PID: " .. (current_pid or "nil"))
    
    -- Always remove the lock file when this function is called
    -- This ensures the lock is released even if PID detection fails
    os.execute('rm -f ' .. lock_file)
    log_message("Removed lock file (PID: " .. (saved_pid_str or "unknown") .. ")")
    
    -- Remove network restart flag file
    os.execute('rm -f ' .. restart_flag_file)
    log_message("Removed network restart flag file")
end


-- Function to check the status of the WANMAP interface and bring it up if necessary
local function check_and_ifup_wanmap()
        local handle = io.popen("ubus call network.interface.wanmap status")
        local result = handle:read("*a")
        handle:close()

        if result:find('"up": true') then
            log_message("WANMAP interface is UP")
        elseif result:find('"up": false') then
            log_message("WANMAP interface is DOWN, bringing it up...")
            local success = interface_up("wanmap")
            if not success then
                log_message("Failed to bring up wanmap interface")
            end
        else
            -- log_message("WANMAP interface not found, skipping ifup...")
        end
 end


-- Function to get the interface name from UCI
local function get_ifname(logical)
    local dev = uci:get("network", logical, "device") or uci:get("network", logical, "ifname") or ""
    -- allow only iface-like tokens (letters, digits, _, -, .); otherwise reject
    if not dev:match("^[%w%.%-%_]+$") then
        log_message("Invalid interface name from UCI: " .. tostring(dev))
        return ""
    end
    return dev
end

local function get_l3_device(logical)
    local dev = get_ifname(logical)
    if dev ~= "" then
        return dev
    end

    local status = sys.exec("ubus call network.interface." .. logical .. " status 2>/dev/null")
    local data = json.parse(status) or {}
    dev = data.l3_device or data.device or data.ifname or ""
    if dev ~= "" and dev:match("^[%w%.%-%_]+$") then
        return dev
    end

    if logical and logical:match("^[%w%.%-%_]+$") then
        local check = sys.exec("ip link show dev " .. logical .. " 2>/dev/null")
        if check ~= "" then
            return logical
        end
    end

    return ""
end

-- Get current WAN /64 prefix from kernel routes or WAN GUA (RA-only fallback)
local function get_wan_prefix64_from_kernel()
    local wan_dev = get_l3_device("wan6") or get_ifname("wan") or ""
    if wan_dev == "" then
        return nil
    end

    local routes = sys.exec("ip -6 route show dev " .. wan_dev .. " 2>/dev/null")
    for line in routes:gmatch("[^\n]+") do
        local prefix = line:match("^([%x:]+::/64)%s")
        if prefix and not prefix:match("^fe80:") then
            return prefix:gsub("/64$", "")
        end
    end

    local addr = sys.exec("ip -6 addr show dev " .. wan_dev .. " scope global 2>/dev/null")
    local addr_str = addr:match("inet6%s+([%x:]+)/%d+")
    if addr_str then
        local parts = {}
        for p in addr_str:gmatch("[^:]+") do
            table.insert(parts, p)
        end
        if #parts >= 4 then
            return string.format("%s:%s:%s:%s::", parts[1], parts[2], parts[3], parts[4])
        end
    end

    return nil
end

-- Normalize an IPv6 prefix string by removing CIDR suffix if present.
local function normalize_ipv6_prefix(prefix)
    if not prefix then
        return ""
    end
    return tostring(prefix):gsub("/%d+$", "")
end

-- Function to extract the first four sections of an IPv6 address and convert it to ::/56
local function extract_ipv6_56(wan_ipv6)
    local ipv6 = ip.IPv6(wan_ipv6)
    if ipv6 then
        return ipv6:network(56):string()
    end
    return wan_ipv6 -- Return original address if parsing fails
end

local function extract_ipv6_64(wan_ipv6)
    local ipv6 = ip.IPv6(wan_ipv6)
    if ipv6 then
        local prefix = ipv6:network(64):string()
        return prefix:gsub("/64$", "")
    end
    return nil
end

local function get_current_wan_prefix64(wan_ipv6, ipv6Prefix)
    if ipv6Prefix and ipv6Prefix ~= "" and ipv6Prefix ~= "not found" then
        local p64 = extract_ipv6_64(ipv6Prefix)
        if p64 and p64 ~= "" then
            return p64
        end
    end

    local prefix = get_wan_prefix64_from_kernel()
    if prefix and prefix ~= "" then
        return prefix
    end

    if wan_ipv6 and wan_ipv6 ~= "" and wan_ipv6 ~= "0000:0000:0000:0000:0000:0000:0000:0000" then
        local p64 = extract_ipv6_64(wan_ipv6)
        if p64 and p64 ~= "" then
            return p64
        end
    end

    return nil
end

local function get_wan_gua64_from_kernel()
    local wan_dev = get_l3_device("wan6") or get_ifname("wan") or ""
    if wan_dev == "" then
        return nil
    end

    local addr = sys.exec("ip -6 addr show dev " .. wan_dev .. " scope global 2>/dev/null")
    for addr_str, _, flags in addr:gmatch("inet6%s+([%x:]+)/(%d+)([^\n]*)") do
        local lower_flags = (flags or ""):lower()
        if not lower_flags:match("tentative") and not lower_flags:match("dadfailed") then
            local gua64 = extract_ipv6_64(addr_str)
            if gua64 and gua64 ~= "" then
                return gua64
            end
        end
    end

    return nil
end

local function get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
    local prefix64 = get_current_wan_prefix64(wan_ipv6, ipv6Prefix) or ""
    local prefix_len = tonumber(prefixLength)
    if not prefix_len and ipv6Prefix and ipv6Prefix ~= "" and ipv6Prefix ~= "not found" then
        prefix_len = tonumber(tostring(ipv6Prefix):match("/(%d+)$"))
    end

    local gua64 = get_wan_gua64_from_kernel() or ""
    if gua64 == "" and wan_ipv6 and wan_ipv6 ~= "" and wan_ipv6 ~= "0000:0000:0000:0000:0000:0000:0000:0000" then
        gua64 = extract_ipv6_64(wan_ipv6) or ""
    end

    if not prefix_len and gua64 ~= "" then
        prefix_len = 64
    end

    local prefix_len_str = prefix_len and tostring(prefix_len) or ""
    local signature = string.format(
        "p64=%s;plen=%s;g64=%s",
        prefix64 ~= "" and prefix64 or "-",
        prefix_len_str ~= "" and prefix_len_str or "-",
        gua64 ~= "" and gua64 or "-"
    )

    return {
        prefix64 = prefix64,
        prefix_len = prefix_len_str,
        gua64 = gua64,
        sig = signature
    }
end

local function update_wan6_cur_prefix(state)
    local changed = false
    local created = false

    if type(state) ~= "table" then
        return
    end

    local prefix64 = state.prefix64 or ""
    local prefix_len = state.prefix_len or ""
    local gua64 = state.gua64 or ""
    local signature = state.sig
    if not signature or signature == "" then
        signature = string.format(
            "p64=%s;plen=%s;g64=%s",
            prefix64 ~= "" and prefix64 or "-",
            prefix_len ~= "" and tostring(prefix_len) or "-",
            gua64 ~= "" and gua64 or "-"
        )
    end

    local function set_or_delete(option, value)
        local current = uci:get("ca_setup", "map", option)
        if value and value ~= "" then
            local new_val = tostring(value)
            if current ~= new_val then
                uci:set("ca_setup", "map", option, new_val)
                changed = true
            end
        elseif current ~= nil then
            uci:delete("ca_setup", "map", option)
            changed = true
        end
    end

    if not uci:get("ca_setup", "map") then
        uci:section("ca_setup", "settings", "map", {})
        created = true
    end

    set_or_delete("cur_prefix", prefix64)
    set_or_delete("cur_prefix_len", prefix_len)
    set_or_delete("cur_gua64", gua64)
    set_or_delete("cur_sig", signature)

    if changed or created then
        uci:commit("ca_setup")
        log_message("Stored current wan6 state: " .. signature)
    end
end

local function get_saved_wan_state_signature(section_name)
    local saved_sig = uci:get("ca_setup", section_name, "last_wan_sig")
    if saved_sig and saved_sig ~= "" then
        return saved_sig
    end
    return nil
end

local function save_last_wan_state(section_name, cur_state)
    if cur_state and cur_state.sig and cur_state.sig ~= "" then
        uci:set("ca_setup", section_name, "last_wan_sig", cur_state.sig)
    else
        uci:delete("ca_setup", section_name, "last_wan_sig")
    end
end

local function should_skip_hotplug_reconfig(section_name, cur_state, from_hotplug)
    if not from_hotplug then
        return false
    end

    local saved_sig = get_saved_wan_state_signature(section_name)
    local cur_sig = cur_state and cur_state.sig or nil
    if saved_sig and cur_sig and saved_sig == cur_sig then
        log_message("IPv6 /64 state unchanged (" .. cur_sig .. "), skipping reconfiguration")
        return true
    end

    log_message("IPv6 /64 state changed from " .. (saved_sig or "unknown") .. " to " .. (cur_sig or "unknown"))
    return false
end


-- Safely concatenate ipv6_56 and ipv6_ifaceid to avoid '::::'
local function concat_ipv6_prefix_and_ifaceid(prefix, ifaceid)
    prefix = normalize_ipv6_prefix(prefix)
    prefix = prefix:gsub(":+$", "")
    ifaceid = ifaceid:gsub("^:+", "")
    return prefix .. "::" .. ifaceid
end


-- Retrieve IP address, prefix, and route using ifstatus wan6 --
local function getIPv6_wan_status()
    local wan_iface = get_ifname("wan6")
    if not wan_iface then
        return "0000:0000:0000:0000:0000:0000:0000:0000", "not found", "not found", "not found", "not found"
    end

    local handle = io.popen("ubus call network.interface.wan6 status")
    local result = handle:read("*a")
    handle:close()

    local data = json.parse(result)
    local wan_ipv6 = "0000:0000:0000:0000:0000:0000:0000:0000"
    local ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = "not found", "not found", "not found", "not found", "not found", "not found"

    if data then
        if data["ipv6-prefix"] and data["ipv6-prefix"][1] then
            ipv6Prefix = data["ipv6-prefix"][1].address or ipv6Prefix
            prefixLength = data["ipv6-prefix"][1].mask or prefixLength
            log_message("IPv6 Prefix: " .. ipv6Prefix .. ", Prefix Length: " .. prefixLength)
        end

        if data["route"] and data["route"][1] then
            route_target = data["route"][1].target or route_target
            route_mask = data["route"][1].mask or route_mask
            log_message("Route Target: " .. route_target .. ", Route Mask: " .. route_mask)
        end
        
        if data["ipv6-address"] and data["ipv6-address"][1] then
            wan_ipv6 = data["ipv6-address"][1].address or wan_ipv6
            log_message("WAN IPv6 Address: " .. wan_ipv6)
            if prefixLength == "not found" and data["ipv6-address"][1].mask then
                prefixLength = data["ipv6-address"][1].mask
            end
        elseif data["ipv6-prefix"] and data["ipv6-prefix"][1] and data["ipv6-prefix"][1]["assigned"] and data["ipv6-prefix"][1]["assigned"]["wan6"] then
            wan_ipv6 = data["ipv6-prefix"][1]["assigned"]["wan6"].address or wan_ipv6
            log_message("Assigned WAN6 IPv6 Address: " .. wan_ipv6)
        elseif wan_ipv6 == "0000:0000:0000:0000:0000:0000:0000:0000" and data["ipv6-prefix"] and data["ipv6-prefix"][1] then
            wan_ipv6 = ipv6Prefix
            log_message("Assigned temp WAN IPv6 Address : " .. wan_ipv6)
        end
    else
        log_message("No data returned from ubus call")
    end

    local prefix_num = tonumber(prefixLength)
    if not prefix_num then
        prefix_num = 64
    end
    prefixLength = prefix_num
    -- local ipv6_fixlen = (prefixLength == 56) and 56 or 64
    local ipv6_fixlen = (prefix_num == 56) and 56 or ((prefix_num == 60) and 60 or 64)
    local ipv6_56 = extract_ipv6_56(wan_ipv6)
    log_message("IPv6 Prefix Length: " .. ipv6_fixlen)
    return wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen
end


-- Helper function to check if an IPv4 address is private (RFC1918)
local function is_private_ipv4(ip)
    return ip and (ip:match("^10%.") or ip:match("^192%.168%.") or 
           ip:match("^172%.(1[6-9]|2[0-9]|3[0-1])%."))
end


-- Function to check the first hop and return under_router status
local function check_under_router(wan_interface, wan6_interface)

    -- Check if WAN has a private IP nexthop
    local wan_status_json = sys.exec("ifstatus wan")
    local nexthop = wan_status_json and wan_status_json:match('"nexthop"%s*:%s*"([^"]+)"')
    if nexthop and is_private_ipv4(nexthop) then
        under_router = 1
        log_message("Upstream IPv4 router is a private IP (" .. nexthop .. "). Setting under_router=1.")
        return under_router
    end

    -- Check first hop with traceroute
    local traceroute_output = sys.exec("traceroute -n -m 1 8.8.8.8 2>/dev/null")
    local first_hop_ip = traceroute_output:match("\n%s*1%s+(%d+%.%d+%.%d+%.%d+)") or
                         traceroute_output:match("^%s*1%s+(%d+%.%d+%.%d+%.%d+)")

    -- If first hop is found through traceroute
    if first_hop_ip then
        under_router = is_private_ipv4(first_hop_ip) and 1 or 0
        log_message("Connected to " .. (under_router == 1 and "RFC1918 PRIVATE IP (under_router=1): " 
                    or "CGNAT/GLOBAL IP (under_router=0): ") .. first_hop_ip)
        return under_router
    end
    
    -- Traceroute failed, check interfaces directly
    log_message("Failed to obtain the first hop IP. Checking WAN interface IP assignment.")
    
    -- Determine which interface to check
    local check_iface = wan_interface and wan_interface ~= "" and wan_interface or
                       (wan6_interface and wan6_interface ~= "" and wan6_interface or "wan")
    
    -- Check IPv4 address on the interface
    local ip_link_output = sys.exec("ip addr show dev " .. check_iface)
    for line in ip_link_output:gmatch("[^\r\n]+") do
        local candidate_ip = line:match("inet (%d+%.%d+%.%d+%.%d+)/%d+")
        if candidate_ip and is_private_ipv4(candidate_ip) then
            under_router = 1
            log_message("Detected private IP on WAN interface: " .. candidate_ip .. " (under_router=1).")
            return under_router
        end
    end
    
    -- No private IPv4 found, set under_router to 0 for now
    under_router = 0
    log_message("NO PRIVATE IPv4 detected on the WAN interface.")
    
    -- Check for ULA IPv6 addresses as well
    local ip6_link_output = sys.exec("ip -6 addr show dev " .. check_iface)
    for line in ip6_link_output:gmatch("[^\r\n]+") do
        local candidate_ip6 = line:match("inet6 ([%x:]+)/%d+ scope global")
        if candidate_ip6 then
            -- ULA is fc00::/7 (fcxx:..., fdxx:... are applicable)
            local first_two = candidate_ip6:sub(1, 2):lower() 
            if first_two == "fc" or first_two == "fd" then
                under_router = 1
                log_message("Private IPv6 (ULA) detected on the WAN interface: " .. candidate_ip6 .. " (under_router=1).")
                return under_router
            end
        end
    end
    
    -- Check if we need to review settings due to DHCP AUTO mode
    local WANTYPE = uci:get("ca_setup", "map", "VNE") or "nil"
    if WANTYPE == "DHCP AUTO" then
        log_message("No private addressing detected, but need to review the current setting.")
        samewancheck = "N"
    else
        log_message("No private addressing detected on the WAN interface (under_router=0).")
    end
    
    return under_router
end


-- Function to determine VNE --
local function determineVNE(wan_ipv6)
    -- Create an IPv6 object from the address
    local addr = ip.IPv6(wan_ipv6)
    if not addr then
        return "unknown" -- Invalid IPv6 address
    end
    
    local subnets = {
        { subnet = "2001:f70::/29", vne = "Xpass" },
        { subnet = "2404:7a80::/30", vne = "ipv6_option" },
        { subnet = "2404:7a84::/30", vne = "ipv6_option" },
        { subnet = "2400:4050::/30", vne = "OCN_virtualconnect" },
        { subnet = "2400:4150::/30", vne = "OCN_virtualconnect" },
        { subnet = "240b::/16", vne = "v6_plus" },
        { subnet = "2409:10::/30", vne = "transix" },
        { subnet = "2409:250::/30", vne = "transix" },
        { subnet = "2405:6580::/29", vne = "v6_connect" },
        { subnet = "2408::/16", vne = "NTT_EAST" },
        { subnet = "2001::/16", vne = "NTT_WEST" } 
    }
    
    -- Check each subnet to determine the VNE
    for _, entry in ipairs(subnets) do
        local subnet = ip.IPv6(entry.subnet)
        if subnet and subnet:contains(addr) then
            return entry.vne
        end
    end
    
    return "unknown"
end


-- Helper function to check connection when in DHCP AUTO mode
local function check_connection_if_dhcp_auto()
    local WANTYPE = uci:get("ca_setup", "map", "VNE") or "nil"
    if WANTYPE == "DHCP AUTO" then
        -- Fallback process to recover in case internet connection is not available
        local handle = io.popen("ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || echo fail")
        local result = handle:read("*a")
        handle:close()
        if string.find(result, "fail") then
            log_message("Need to confirm WAN network setting...")
            samewancheck = "N"
        end
    end
end


-- Function to check current IPv4 routing path without network reconfiguration
local function check_ipv4_path_without_reconfiguration(hgw_ip)
    hgw_ip = hgw_ip or "192.168.1.1"
    log_message("Checking IPv4 routing path...")
    
    -- First check if IPv4 connectivity is available with current settings
    local ping_cmd = "ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1"
    local ping_success = os.execute(ping_cmd) == 0
    
    if not ping_success then
        log_message("IPv4 connectivity check FAILED: Assuming HGW's MAP-E is disabled")
        return "disabled"
    end
    
    -- IPv4 connectivity is OK, check routing path with traceroute
    log_message("IPv4 connectivity check PASSED: Analyzing routing path...")
    local trace_cmd = "traceroute -n -m 3 8.8.8.8 2>/dev/null"
    local handle = io.popen(trace_cmd)
    local trace_result = handle:read("*a")
    handle:close()
    
    -- Get current default gateway IP
    local gw_cmd = "ip route show | grep default | awk '{print $3}'"
    local gw_handle = io.popen(gw_cmd)
    local gateway_ip = gw_handle:read("*a"):gsub("%s+$", "")
    gw_handle:close()
    
    -- Check traceroute output
    log_message("Traceroute result:\n" .. trace_result)
    
    -- Check if gateway IP or HGW IP appears in route
    if gateway_ip and gateway_ip ~= "" and trace_result:find(gateway_ip) then
        log_message("IPv4 packets are routed through HGW (IP:" .. gateway_ip .. "). HGW's MAP-E is enabled.")
        return "hgw_enabled"
    elseif trace_result:find(hgw_ip) then
        log_message("IPv4 packets are routed through HGW (IP:" .. hgw_ip .. "). HGW's MAP-E is enabled.")
        return "hgw_enabled"
    else
        -- Check if CE's WAN IP appears in first hop
        local wan_ip_cmd = "ip addr show dev " .. wan_interface .. " | grep 'inet ' | awk '{print $2}' | cut -d/ -f1"
        local wan_handle = io.popen(wan_ip_cmd)
        local wan_ip = wan_handle:read("*a"):gsub("%s+$", "")
        wan_handle:close()
        
        if wan_ip and wan_ip ~= "" and trace_result:find(wan_ip) then
            log_message("IPv4 packets are routed through CE (IP:" .. wan_ip .. "). CE is handling MAP-E translation.")
            return "ce_enabled"
        else
            -- No private IP found in route, assuming CE is handling MAP-E
            log_message("No HGW IP found in route. CE is handling MAP-E translation.")
            return "ce_enabled"
        end
    end
end


-- Function to check the presence of NTT HGW and reflect the result
local function check_ntt_hgw()

    -- 1. HANDLE DEBUG MODE
    if debug_nohgw == 1 then
        under_router = 3
        log_message("Debug mode: Forcing under_router = 3 (HGW IPoE Disabled or not available)")
        return "Disabled"
    end

    -- 2. GET DEFAULT GATEWAY
    local handle = io.popen("ip route show | grep default | awk '{print $3}'")
    local gw_ip = ""
    if handle then
        gw_ip = handle:read("*a")
        handle:close()
        gw_ip = gw_ip and gw_ip:match("%S+") or ""
    end

    -- 3. CHECK FOR NTT HGW PRESENCE
    -- Build URLs to check (Priority: GW → 192.168.1.1 → ntt.setup)
    local check_urls = {}
    if gw_ip ~= "" then
        table.insert(check_urls, "http://" .. gw_ip .. ":8888/t/")
    end
    table.insert(check_urls, "http://192.168.1.1:8888/t/")
    table.insert(check_urls, "http://ntt.setup:8888/t/")

    -- Check HTTP status with HEAD request, if 200 is returned, NTT HGW is detected
    local hgw_found = false
    for _, url in ipairs(check_urls) do
        local cmd = string.format(
            "curl --connect-timeout 2 -m 3 -s --head '%s' -o /dev/null -w '%%{http_code}'",
            url
        )
        local handle = io.popen(cmd)
        local result = ""
        if handle then
            result = handle:read("*a")
            handle:close()
        end

        if result:find("200") then
            log_message("NTT HGW detected: " .. url)
            under_router = 2
            hgw_found = true
            break
        end
    end

    -- If HGW not found, return early
    if not hgw_found then
        log_message("NTT HGW not detected")
        return "NO-HGW"
    end

-- For DS-LITE VNEs, if HGW is detected, set under_router=3 and return
if VNE == "transix" or VNE == "v6_connect" or VNE == "Xpass" then
    under_router = 3
    return "DS-LITE with HGW"
end

-- 4. CHECK IPOE SOFTWARE STATUS BY VNE TYPE
local final_status = "NOT FOUND"
local urls = {}

-- Special handling for OCN_virtualconnect
if VNE == "OCN_virtualconnect" then
    -- For OCN, skip JSON and check IPv4 path directly
    local hgw_ipv4 = gw_ip ~= "" and gw_ip or "192.168.1.1"
    local path_status = check_ipv4_path_without_reconfiguration(hgw_ipv4)
    if path_status == "hgw_enabled" then
        log_message("HGW has active MAP-E. CE will operate in DHCP AUTO mode.")
        under_router = 2
        final_status = "Enabled"
        VNE = "DHCP AUTO"
    else
        log_message("HGW's MAP-E is disabled or unavailable. CE will connect using OCN Virtual Connect.")
        under_router = 3
        final_status = "Disabled"
    end
    log_message("NTT HGW IPoE software status: " .. final_status)
    return final_status

-- Build URLs for v6_plus
elseif VNE == "v6_plus" then
    if gw_ip ~= "" then
        table.insert(urls, "http://" .. gw_ip .. ":8888/enabler.ipv4/check")
    end
    table.insert(urls, "http://192.168.1.1:8888/enabler.ipv4/check")
    table.insert(urls, "http://ntt.setup:8888/enabler.ipv4/check")

-- Build URLs for ipv6_option
elseif VNE == "ipv6_option" then
    if gw_ip ~= "" then
        table.insert(urls, "http://" .. gw_ip .. ":8888/biglobe.ipv4/check")
    end
    table.insert(urls, "http://192.168.1.1:8888/biglobe.ipv4/check")
    table.insert(urls, "http://ntt.setup:8888/biglobe.ipv4/check")

-- Unknown VNE type
else
    log_message("Unknown VNE: " .. tostring(VNE))
    return "UNKNOWN-VNE"
end

-- 5. CHECK IPOE STATUS FOR EACH URL (only for v6_plus and ipv6_option)
for _, url in ipairs(urls) do
    -- Fetch status using GET request
    local cmd = string.format(
        "curl --connect-timeout 2 -m 3 -s -X GET '%s' -H 'Accept: application/json'",
        url
    )
    local handle = io.popen(cmd)
    local res = ""
    if handle then
        res = handle:read("*a")
        handle:close()
    end

    -- Extract content from parentheses if present
    local matched_data = res:match("%b()")
    if matched_data then
        matched_data = matched_data:sub(2, -2)
        res = matched_data
    end

    -- Process response if not empty
    if res and res ~= "" then
        local json_data = json.parse(res)
        if VNE == "v6_plus" or VNE == "ipv6_option" then
            -- Handle v6_plus and ipv6_option format
            if json_data and json_data.status then
                if json_data.status == "OFF" then
                    under_router = 3
                    final_status = "Disabled"
                    check_connection_if_dhcp_auto()
                    break
                elseif json_data.status == "ON" then
                    under_router = 2
                    final_status = "Enabled"
                    VNE = "DHCP AUTO"
                    break
                end
            end
        else
            log_message("Unsupported VNE response format for: " .. tostring(VNE))
        end
    end
end

log_message("NTT HGW IPoE software status: " .. final_status)
return final_status
end


-- Register script for startup
local function reg_map_startup()
    local restart_flag_file = '/tmp/mapv6_network_restart_flag'
    
    -- Updated command to check for restart flag before executing the script
    local commandToAdd = string.format(
        "grep -Fq '%s' %s || sed -i '/^exit 0/i \\\\([ -n \"$(uci get ca_setup.map 2>/dev/null)\" ] && ([ -f %s ] || (sleep $((RANDOM %% 540 + 60)); lua %s --from-boot)) || ([ -f %s ] || (sleep 15; lua %s --from-boot))) &' %s",
        script_path, rcLocalPath, restart_flag_file, script_path, restart_flag_file, script_path, rcLocalPath
    )
    os.execute(commandToAdd)
end

-- Register script for Map-e static IP startup
local function reg_map_startup_static()
    local restart_flag_file = '/tmp/mapv6_network_restart_flag'
    local commandToAdd = string.format(
        "grep -Fq '%s -s2' %s || sed -i '/^exit 0/i \\\\([ -f %s ] || (sleep $((RANDOM %% 540 + 60)); lua %s -s2 --from-boot --random-delay)) &' %s",
        script_path, rcLocalPath, restart_flag_file, script_path, rcLocalPath
    )
    os.execute(commandToAdd)
end

-- Remove from startup
local function unreg_map_startup()
    local commandToRemove = "sed -i '/mapv6/d' /etc/rc.local"
    os.execute(commandToRemove)
end


-- Function to extract the first 32-bit and 40-bit segments of the WAN IPv6 address
local function wan32_40(wan_ipv6)
    local ipv6 = ip.IPv6(wan_ipv6)
    if not ipv6 then
        return wan_ipv6 .. "::", wan_ipv6 .. "::"
    end
    
    local wan32_ipv6 = ipv6:network(32):string()
    local addr_parts = {}
    local addr_str = ipv6:string()

    for part in addr_str:gmatch("[^:]+") do
        table.insert(addr_parts, part)
    end

    if #addr_parts >= 3 then
        local third_part = addr_parts[3]
        if #third_part >= 2 then
            third_part = third_part:sub(1, 2) .. "00"
        end
        local wan40_ipv6 = addr_parts[1] .. ":" .. addr_parts[2] .. ":" .. third_part .. "::"
        return wan32_ipv6, wan40_ipv6
    end
    
    return wan32_ipv6, wan32_ipv6
end


-- Encryption function
local function encrypt_data(data, keyword)
    local key = openssl.digest.digest("sha256", keyword, true)
    local iv = key:sub(1, 16)
    local cipher = openssl.cipher.get("aes-256-cbc")
    local encrypted, err = cipher:encrypt(data, key, iv)
    if not encrypted then
        return nil, "Encrypt error: " .. err
    end
    local hex = openssl.hex(encrypted)
    return hex
end


-- Hotplug handling for the WAN interface
local function check_wan_hotplug()
    -- wan6 prefix/address change handler
    os.execute([=[
cat <<'EOF' > /etc/hotplug.d/iface/50-wan6-prefix
#!/bin/sh
[ "$INTERFACE" = "wan6" ] || exit 0
case "$ACTION" in
    ifup|ifupdate) ;;
  *) exit 0 ;;
esac

FLAG_FILE="/tmp/hotplug_initialized"
RESTART_FLAG="/tmp/mapv6_network_restart_flag"
SCRIPT="/usr/lib/lua/mapv6.lua"

# honor init and restart guards
[ -f "$FLAG_FILE" ] || exit 0
[ -f "$RESTART_FLAG" ] && exit 0

# wait briefly for tentative addresses to settle
sleep 5

to_prefix64() {
    local addr="$1"
    [ -n "$addr" ] || return 1
    addr="${addr%%/*}"
    local p64
    p64="$(/usr/bin/lua /usr/lib/lua/mapv6.lua -prefix64 "$addr" 2>/dev/null | head -n1)"
    [ -n "$p64" ] || return 1
    printf '%s' "$p64"
    return 0
}

collect_wan6_state() {
    local status
    status="$(ubus call network.interface.wan6 status 2>/dev/null)"

    WAN_DEV="$(echo "$status" | jsonfilter -e '@.l3_device' 2>/dev/null)"
    [ -z "$WAN_DEV" ] && WAN_DEV="$(echo "$status" | jsonfilter -e '@.device' 2>/dev/null)"
    [ -z "$WAN_DEV" ] && WAN_DEV="wan6"

    CUR_PREFIX="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][0].address' 2>/dev/null)"
    [ -z "$CUR_PREFIX" ] && CUR_PREFIX="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][1].address' 2>/dev/null)"
    CUR_PREFIXLEN="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][0].mask' 2>/dev/null)"
    [ -z "$CUR_PREFIXLEN" ] && CUR_PREFIXLEN="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][1].mask' 2>/dev/null)"
    CUR_PREFIX64="$(to_prefix64 "$CUR_PREFIX")"

    CUR_GUA="$(echo "$status" | jsonfilter -e '@["ipv6-address"][0].address' 2>/dev/null)"
    [ -z "$CUR_GUA" ] && CUR_GUA="$(echo "$status" | jsonfilter -e '@["ipv6-address"][1].address' 2>/dev/null)"
    if [ -z "$CUR_GUA" ]; then
        CUR_GUA="$(ip -6 addr show dev "$WAN_DEV" scope global 2>/dev/null | awk '/inet6 /{print $2}' | sed -n 's#/.*##p' | grep -E '^[23]' | head -n1)"
    fi
    CUR_GUA64="$(to_prefix64 "$CUR_GUA")"

    if [ -z "$CUR_PREFIX64" ]; then
        CUR_PREFIX64="$(ip -6 route show dev "$WAN_DEV" 2>/dev/null | sed -n 's#^\\([0-9A-Fa-f:]*\\)/64.*#\\1#p' | grep -E '^[23]' | head -n1)"
    fi
    if [ -z "$CUR_PREFIX64" ] && [ -n "$CUR_GUA64" ]; then
        CUR_PREFIX64="$CUR_GUA64"
    fi
    if [ -z "$CUR_PREFIXLEN" ] && [ -n "$CUR_GUA64" ]; then
        CUR_PREFIXLEN="64"
    fi

    [ -n "$CUR_PREFIX64" ] || CUR_PREFIX64="-"
    [ -n "$CUR_PREFIXLEN" ] || CUR_PREFIXLEN="-"
    [ -n "$CUR_GUA64" ] || CUR_GUA64="-"
    CUR_SIG="p64=$CUR_PREFIX64;plen=$CUR_PREFIXLEN;g64=$CUR_GUA64"
}

attempt=0
while [ "$attempt" -lt 3 ]; do
    collect_wan6_state
    [ "$CUR_SIG" != "p64=-;plen=-;g64=-" ] && break
    attempt=$((attempt + 1))
    sleep 2
done

SAVED_SIG="$(uci -q get ca_setup.map.cur_sig)"
if [ -z "$SAVED_SIG" ]; then
    if [ "$CUR_PREFIX64" != "-" ]; then
        uci -q set ca_setup.map.cur_prefix="$CUR_PREFIX64"
    fi
    if [ "$CUR_PREFIXLEN" != "-" ]; then
        uci -q set ca_setup.map.cur_prefix_len="$CUR_PREFIXLEN"
    fi
    if [ "$CUR_GUA64" != "-" ]; then
        uci -q set ca_setup.map.cur_gua64="$CUR_GUA64"
    fi
    uci -q set ca_setup.map.cur_sig="$CUR_SIG"
    uci -q commit ca_setup
    logger -t hotplug "wan6 state stored: '$CUR_SIG'"
    exit 0
fi
[ "$CUR_SIG" = "$SAVED_SIG" ] && exit 0
logger -t hotplug "wan6 state changed: '${SAVED_SIG:-none}' -> '$CUR_SIG'"
lua "$SCRIPT" --from-hotplug
EOF
chmod +x /etc/hotplug.d/iface/50-wan6-prefix
]=])

    -- the init flag creator
    os.execute('echo -e \'#!/bin/sh\\nsleep 300\\ntouch /tmp/hotplug_initialized\\nlogger -t hotplug "Hotplug initialized flag created after 300 seconds."\\n\' > /etc/init.d/create_hotplug_flag && chmod +x /etc/init.d/create_hotplug_flag && ln -s /etc/init.d/create_hotplug_flag /etc/rc.d/S99create_hotplug_flag')
end


-- brand check function
local function brand_status()
    local conn = ubus.connect()
    if not conn then error("Failed to connect to ubus") end

    local system_info = conn:call("system", "board", {})
    local model = system_info.model or "nil"
    local brandkey = "NA"
    local brand = "NG"
    if model ~= "nil" then
        model = string.gsub(model, "Qualcomm", "Linksys")
        if string.find(model, "Linksys") then
            brandkey, brand = model:sub(1, 7), "OK"
        end
    end
    return brandkey, brand, model
end

    
-- Register cron timer to check map rules every morning at 4am --
local function check_cron_entry()
    local cron_entry = uci:get("ca_setup", "map", "cron_entry")
    if cron_entry == nil then
        -- Schedule the first run using at (5 minutes from now) when available
        if sys.call("command -v at >/dev/null 2>&1") == 0 then
            local at_cmd = string.format('echo "/usr/bin/lua %s" | at now + 5 minutes', script_path)
            os.execute(at_cmd)
        end

        uci:set("ca_setup", "getmap", "autoipoe","1")
        uci:set("ca_setup", "map", "cron_entry","1")
        uci:commit("ca_setup")
    end
end

-- Remove execution functionality by cron timer and hotplug
local function remove_cron_entry()
    -- Remove cron job
    os.execute("crontab -l 2>/dev/null | grep -v '" .. script_path .. "' | crontab -")
    sys.call("/etc/init.d/cron restart")

    -- Remove hotplug handling scripts
    os.execute('rm -f /etc/hotplug.d/iface/50-wan6-prefix /etc/hotplug.d/iface/99-ipip-prefix-change')
    os.execute('rm -f /tmp/hotplug_initialized')
    os.execute('rm -f /etc/init.d/create_hotplug_flag')
    os.execute('rm -f /etc/rc.d/S99create_hotplug_flag')

    -- Reset Auto IPOE setting to 0
    uci:delete("ca_setup", "map", "cron_entry")
    uci:delete("ca_setup", "map", "check_hour")
    uci:delete("ca_setup", "map", "check_minute")
    uci:set("ca_setup", "getmap", "autoipoe","0")
    uci:commit("ca_setup")
end


-- Function to schedule the next run of the script based on VNE
local function schedule_next_run(from_boot, mode)
    -- Set a daily check time based on VNE
    local check_hour, check_minute
    math.randomseed(os.time())
    
    -- Get current time
    local current_time = os.time()
    local current_time_table = os.date("*t", current_time)

    local target_vne = (mode == "ocn_static") and "OCN_virtualconnect" or VNE
    
    if target_vne == "v6_plus" or target_vne == "ipv6_option" then
        -- Random interval between 3-24 hours (180-1440 minutes)
        local minutes_from_now = math.random(180, 1440)
        local next_time = current_time + (minutes_from_now * 60)
        local next_time_table = os.date("*t", next_time)
        
        check_hour = next_time_table.hour
        check_minute = next_time_table.min
        
        log_message("Setting " .. target_vne .. " next check after " .. math.floor(minutes_from_now/60) .. 
                   " hours " .. (minutes_from_now % 60) .. " minutes at " ..
                   check_hour .. ":" .. (check_minute < 10 and "0" or "") .. check_minute)
    elseif target_vne == "OCN_virtualconnect" then
        -- Random interval between 12-24 hours (720-1440 minutes)
        local minutes_from_now = math.random(720, 1440)
        local next_time = current_time + (minutes_from_now * 60)
        local next_time_table = os.date("*t", next_time)
        
        check_hour = next_time_table.hour
        check_minute = next_time_table.min
        
        local label = (mode == "ocn_static") and "OCN_virtualconnect (static)" or "OCN_virtualconnect"
        log_message("Setting " .. label .. " next check after " .. math.floor(minutes_from_now/60) .. 
                   " hours " .. (minutes_from_now % 60) .. " minutes at " ..
                   check_hour .. ":" .. (check_minute < 10 and "0" or "") .. check_minute)
    else
        -- Fixed 4 AM for other VNEs
        check_hour = 4
        check_minute = 0
        log_message("Setting standard daily check at 4:00 AM")
    end
    
    -- Create cron entry: minute hour * * *
    local cron_time = string.format("%d %d * * *", check_minute, check_hour)
    
    -- Remove any existing cron job for this script
    os.execute("crontab -l 2>/dev/null | grep -v '" .. script_path .. "' | crontab -")
    
    -- Build cron command (static mode runs -s2)
    local cron_command = "lua " .. script_path
    if mode == "ocn_static" then
        cron_command = cron_command .. " -s2"
    end
    cron_command = cron_command .. " --random-delay"
    
    -- Add the new cron job with a random delay parameter
    os.execute("(crontab -l 2>/dev/null; echo '" .. cron_time .. " " .. cron_command .. "') | crontab -")
    sys.call("/etc/init.d/cron restart")
    
    -- Save the check time to UCI for reference
    uci:set("ca_setup", "map", "check_hour", check_hour)
    uci:set("ca_setup", "map", "check_minute", check_minute)
    uci:set("ca_setup", "map", "cron_entry", "1")
    uci:commit("ca_setup")
    
    log_message("Scheduled next regular check at " .. check_hour .. ":" .. 
               (check_minute < 10 and "0" or "") .. check_minute .. " ... done")
               
    -- If we're already running from a boot event, don't schedule immediate run
    if not from_boot then
        log_message("Current execution not from boot, normal scheduling applied")
    else
        log_message("Current execution from boot, cron schedule updated")
    end
end


-- Function to check the number of times map rules have been fetched and handle initial execution
local function mapcount_check()
    local mapcount = uci:get("ca_setup", "map", "mapcount")

    if mapcount == nil then
        -- Routine for initial execution and various registrations
        reg_map_startup()
        check_wan_hotplug()
        check_cron_entry()
        mapcount = 1
    else
        init_execute = 1
        mapcount = mapcount + 1
    end

    return mapcount, init_execute
end


-- Check the time when the map rules were saved
local function reloadtimer()
    local currentTime = os.time()
    local savedTimeStr = uci:get("ca_setup", "map", "ostime") or 0

    -- If the saved time is not found, consider it the first execution
    if not savedTimeStr or savedTimeStr == "0" then
        return "Y"
    end

    -- If the saved time is invalid, consider it the first execution
    local savedTime = tonumber(savedTimeStr)
    if not savedTime then
        return "Y"
    end

    local remaining_time
    if savedTime == 0 then
        remaining_time = 0
    else
        remaining_time = 600 - (currentTime - savedTime)
    end
    if remaining_time > 0 then  
        if samewancheck == "N" then -- In case the IPv6 address has changed
            log_message("Detected a change in IPv6 address, skipping duplicate execution timer.")
            return "Y"
        else
            log_message("You can execute in " .. remaining_time .. " seconds.")
            script_lock_disable()
            discard_temp_logs()
            os.exit()
        end
    else
        return "Y"
    end
end


-- Decryption function
local function decryptedData(hexEncryptedData)
    local function hex_to_binary(hex)
        return (hex:gsub('..', function(cc)
            return string.char(tonumber(cc, 16))
        end))
    end
    local encryptedData = hex_to_binary(hexEncryptedData)
    local key = openssl.digest.digest("sha256", urkey, true)
    local iv = key:sub(1, 16)
    local cipher = openssl.cipher.get("aes-256-cbc")
    local decrypted, err = cipher:decrypt(encryptedData, key, iv)
    return decrypted or "error"
end


-- Function to save configuration for V6 PLUS
local function save_ca_setup_config(json_data)
    local data = json.parse(json_data)
    local fmrStr = json.stringify(data.fmr)
    local endmr, err = encrypt_data(data.dmr, urkey)
    local enfmrStr, err = encrypt_data(fmrStr, urkey)
    uci:section("ca_setup", "settings", "map", {
        dmr = endmr,
        ipv6_fixlen = ipv6_fixlen,
        fmr = enfmrStr,
        time = timestamp,
        ostime = os.time(),
        model = sysinfo_model,
        VNE = VNE,
        mapcount = mapcount,
    })
    uci:commit("ca_setup")
    id = data.id
end


-- Function to convert OCN JSON data format
local function generateJsonFromMapRules(json_data)
    local fmr = {}

    -- Loop through the basicMapRules array and process
    for _, rule in ipairs(json_data.basicMapRules) do
        local ipv6 = rule.ipv6Prefix and rule.ipv6PrefixLength and (rule.ipv6Prefix .. "/" .. rule.ipv6PrefixLength) or ""
        local ipv4 = rule.ipv4Prefix and rule.ipv4PrefixLength and (rule.ipv4Prefix .. "/" .. rule.ipv4PrefixLength) or ""
        local ea_length = tonumber(rule.eaBitLength) or 0
        local psid_offset = tonumber(rule.psIdOffset) or 0

        table.insert(fmr, {
            br_ipv6 = rule.brIpv6Address,
            ipv6 = ipv6,
            ipv4 = ipv4,
            ea_length = ea_length,
            psid_offset = psid_offset
        })
    end

    -- Convert Lua table to JSON string and return
    return json.stringify(fmr)
end


-- Function to save configuration for OCN
local function save_ca_setup_config_ocn(json_data)
    local fmrStr = generateJsonFromMapRules(json_data)
    local enfmrStr, err = encrypt_data(fmrStr, urkey)
    uci:section("ca_setup", "settings", "map", {
        dmr = "OCN", -- OCN has br_ipv6, but the value is referenced during retries
        ipv6_fixlen = ipv6_fixlen,
        fmr = enfmrStr,
        time = timestamp,
        ostime = os.time(),
        model = sysinfo_model,
        VNE = VNE,
        mapcount = mapcount,
    })
    uci:commit("ca_setup")
end

-- Function to save configuration for OCN STATIC
local function save_ca_setup_config_ocn_static(json_data, hostname)
    local fmrStr = generateJsonFromMapRules(json_data)
    local enfmrStr = encrypt_data(fmrStr, urkey)
    uci:section("ca_setup", "settings", "map", {
        dmr = "OCN_STATIC",
        ipv6_fixlen = ipv6_fixlen,
        fmr = enfmrStr,
        time = timestamp,
        ostime = os.time(),
        model = sysinfo_model,
        VNE = VNE,
        mapcount = mapcount,
        hostname = hostname or ""
    })
    uci:commit("ca_setup")
end

-- Function to save configuration for other VNEs
local function save_ca_setup_config_other()
    uci:section("ca_setup", "settings", "map", {
        dmr = "",
        ipv6_fixlen = ipv6_fixlen,
        fmr = "",
        time = timestamp,
        ostime = os.time(),
        model = sysinfo_model,
        VNE = VNE,
        mapcount = mapcount,
    })
    uci:commit("ca_setup")
end

local reset_wan_to_dhcp
local wait_for_wan_ready

local function network_restart_handler(reason, wait_seconds)
    local message = "Applying new setup"
    if reason and reason ~= "" then
        message = message .. " (" .. reason .. ")"
    end
    log_message(message .. "...")

    local linksyswrt = tostring(uci:get("ca_setup", "getmap", "linksyswrt") or "")
    if linksyswrt ~= "1" then
        os.execute("/etc/init.d/network restart")
    end

    if wait_seconds == nil then
        wait_seconds = 10
    end
    if wait_seconds > 0 and wait_for_wan_ready then
        local linksyswrt = tostring(uci:get("ca_setup", "getmap", "linksyswrt") or "")
        if linksyswrt ~= "1" then
            wait_for_wan_ready(wait_seconds)
        end
    end
end


-- Function to revert to DHCP and abort in case of map error
local function map_403_200blank_delete()

    log_message("An error occurred with MAP-E, deleted MAP rules and set to DHCP.")

    interface_down("wanmap")
    samewancheck = "N"
    reset_wan_to_dhcp(true)
            
end

-- Function to revert to DHCP and abort in case of map error
local function map_error_recovery(from_boot)
    from_boot = (from_boot == true)

    log_message("An error occurred with MAP-E, reverting to DHCP and aborting.")
    reset_wan_to_dhcp(true)
            
    network_restart_handler("DHCP auto configuration", 0)
    if not (qsdk and qsdk >= 12.5) then
        os.execute("/etc/init.d/firewall restart")
    end
    schedule_next_run(from_boot)
    script_lock_disable()
    save_logs_to_persistent_storage()
    os.exit()
end


-- Operation reporting function for v6 plus
local function report_operation(manufacturer_code, callback, action, reason, id)

    -- Embed query parameters into the URL
    manufacturer_code = manufacturer_code or "default_manufacturer"
    callback = callback or ""
    action = action or 1 -- action, operation content (1: start operation, 2: stop operation)
    reason = reason or 0 -- reason, 0: Normal operation (start/stop)… Operation start/stop after receiving rules 1: Manual operation (stop/start)… Operation start/stop by user action 2: Address change (start/stop)… Operation start/stop due to IPv6 address change 3: Map rule mismatch (stop)… If there is no matching rule after receiving rules 4: Operating on HGW (stop)… If operating on HGW, etc.
    id = id or "" -- Send the acquired unique hash

    -- Send HTTPS GET request
    local report_url = string.format("https://api.enabler.ne.jp/%s/acct_report?callback=%s&action=%d&reason=%d&id=%s",
                                     manufacturer_code, callback, action, reason, id)
    local handle = io.popen("curl -s -X GET " .. shellquote(report_url) .. " -H 'Accept: application/json'")
    local res = handle:read("*a")
    handle:close()

    -- Check the response directly
    log_message("map acct_report response: " .. (res or "") .. " router_reported action: " .. action .. " reason: " .. reason)

end


-- Rule retrieval reporting function v6 PLUS
local function auto_fetch_data(manufacturer_code, from_boot)
    local attempts = 0

    local function handle_success(json_data)
        save_ca_setup_config(json_data)
        log_message("Successfully retrieved and saved map rules.")
        if samewancheck == "N" and init_execute == 1 then
            report_operation(manufacturer_code, callback, 1, 2, id)
        elseif samewancheck == "N" and init_execute == 0 then
            report_operation(manufacturer_code, callback, 1, 1, id)
        else
            report_operation(manufacturer_code, callback, 1, 0, id)
        end
        return true
    end

    local function handle_retry(message, wait_time, report_action, report_reason)
        if attempts <= 999 then
            report_operation(manufacturer_code, callback, report_action, report_reason, id)
            log_message(attempts .. "th retry attempt is waiting...")
            log_message("Retrying in " .. wait_time .. " seconds.")
            os.execute("sleep " .. wait_time)
            return false
        end
        log_message(message .. " All retries have failed.")
        report_operation(manufacturer_code, callback, report_action, report_reason, id)
        map_error_recovery(from_boot)
        return true
    end

    local function try_fetch()
        attempts = attempts + 1
        local mapurl = "https://api.enabler.ne.jp/" .. manufacturer_code .. "/get_rules"

        local handle = io.popen("curl -s -w '\\nHTTP Status: %{http_code}\\n' -X GET " .. shellquote(mapurl) .. " -H 'Accept: application/json'")
        local result = handle:read("*a")
        handle:close()

        local data, code = result:match("^([%s%S]*)\nHTTP Status: (%d+)\n$")
        code = tonumber(code)

        if code == 200 and data ~= nil then
            local matched_data = data:match("%b()")
            local json_data = matched_data and matched_data:sub(2, -2) or nil

            if json_data and json_data ~= "{}" then
                return handle_success(json_data)
            else
                log_message("Map rule information is blank, unable to operate v6_plus: 200 BLANK")
                if uci:get("ca_setup", "map") then map_403_200blank_delete() end
                math.randomseed(os.time())
                local random_wait_time = math.random(600, 1800)
                return handle_retry("200 blank rule", random_wait_time, 2, 3)
            end

        elseif code == 403 then
            log_message("Failed to retrieve map rules: 403 Forbidden")
            if uci:get("ca_setup", "map") then map_403_200blank_delete() end
            math.randomseed(os.time())
            local random_wait_time = math.random(10800, 86400)
            return handle_retry("403", random_wait_time, 2, 0)
        else
            local errorMessage = code or "URL unreachable"
            log_message("Failed to retrieve map rules: " .. errorMessage)
            
            if attempts <= 999 then
                log_message(attempts .. "th retry attempt is waiting...")
                if not uci:get("ca_setup", "map", "dmr") then interface_down("wanmap") end
                math.randomseed(os.time())
                local random_wait_time = math.random(60, 600)
                log_message("Retrying in " .. random_wait_time .. " seconds.")
                os.execute("sleep " .. random_wait_time)
                return false
            end
            
            log_message("All retries have failed.")
            if not uci:get("ca_setup", "map", "dmr") then
                log_message("Failed to retrieve map rules. Terminating v6_plus operation")
                map_error_recovery(from_boot)
            else
                log_message("Failed to retrieve new map rule data, but continuing v6_plus operation with previously obtained data")
            end
            return true
        end
    end

    while not try_fetch() do end
    check_and_ifup_wanmap()
end


-- Rule retrieval function OCN
local function auto_fetch_data_ocn(manufacturer_code, mode, from_boot)
    local is_static = (mode == "static")
    local attempts = 0

    local function handle_success(json_data)
        local contains_hostname = false
        local hostname
        if json_data and json_data.basicMapRules then
            for _, rule in ipairs(json_data.basicMapRules) do
                if rule.hostName and rule.hostName ~= "" then
                    contains_hostname = true
                    hostname = rule.hostName
                    break
                end
            end
        end

        if contains_hostname and not is_static then
            log_message("OCN static IP configuration detected with hostname: " .. hostname)
            log_message("Static IP detected - Auto IPOE operation will be disabled.")
            unreg_map_startup()
            remove_cron_entry()
            log_message("Disabled mapv6 hotplug, schedule, and execution on reboot")
            map_error_recovery(from_boot)
            return true
        end

        if is_static and not contains_hostname then
            log_message("ERROR: Static MAP-E request but hostName is missing in OCN rules; aborting static module.")
            error("OCN static MAP rule missing hostName")
        end

        -- OCN MAP rule format compliance check (2-6)
        -- Check if basicMapRules exists and is a table
        if not json_data or type(json_data) ~= "table" or not json_data.basicMapRules or type(json_data.basicMapRules) ~= "table" then
            log_message("OCN MAP rule format error: basicMapRules missing or not a table")
            if uci:get("ca_setup", "map") then map_403_200blank_delete() end
            return false
        end
        -- Check each rule for required fields
        for _, rule in ipairs(json_data.basicMapRules) do
            if not (rule.brIpv6Address and rule.ipv6Prefix and rule.ipv6PrefixLength and rule.ipv4Prefix and rule.ipv4PrefixLength and rule.eaBitLength and rule.psIdOffset) then
                log_message("OCN MAP rule format error: missing required fields in basicMapRules")
                if uci:get("ca_setup", "map") then map_403_200blank_delete() end
                return false
            end
        end
        
          if contains_hostname and is_static then
            log_message("OCN static IP configuration accepted in static mode, hostname: " .. hostname)
            save_ca_setup_config_ocn_static(json_data, hostname)
        else
            save_ca_setup_config_ocn(json_data)
        end
        log_message("Successfully retrieved and saved map rules.")
        return true
    end

    local function handle_retry(message, wait_time)
        if attempts <= 999 then
            log_message(attempts .. "th retry attempt is waiting...")
            log_message("Retrying in " .. wait_time .. " seconds.")
            os.execute("sleep " .. wait_time)
            return false
        end
        log_message(message .. " All three retries have failed.")
        map_error_recovery(from_boot)
        return true
    end

    local function try_fetch()
        attempts = attempts + 1
        local fixlen_ocn = (ipv6_fixlen == 60) and 64 or ipv6_fixlen
        local mapurl = "https://rule.map.ocn.ad.jp/?ipv6Prefix=" 
            .. ipv6_56 
            .. "&ipv6PrefixLength=" 
            .. fixlen_ocn
            .. "&code=" 
            .. manufacturer_code

        local curl_insecure_flag = should_skip_cert_verification() and "-k " or ""
        local handle = io.popen("curl " .. curl_insecure_flag .. "-s -w '\\nHTTP Status: %{http_code}\\n' -X GET "
            .. shellquote(mapurl) .. " -H 'Accept: application/json'")
        local result = handle:read("*a")
        handle:close()

        local data, code = result:match("^([%s%S]*)\nHTTP Status: (%d+)\n$")
        code = tonumber(code)

        if code == 200 and data ~= nil then
            local json_data = json.parse(data)
            if json_data and next(json_data) then
                return handle_success(json_data)
            else
                log_message("Map rule information is blank, unable to operate OCN_virtualconnect: 200 BLANK")
                if uci:get("ca_setup", "map") then map_403_200blank_delete() end
                local wait_time = attempts <= 4 
                    and (60 * (2 ^ (attempts - 1))) -- 1st: 60sec, 2nd: 120sec, 3rd: 240sec, 4th: 480sec
                    or 480 -- 5th and beyond: 480sec
                
                return handle_retry("200 blank rule", wait_time)
            end

        elseif code == 403 then
            log_message("Failed to retrieve map rules: 403 Forbidden")
            if uci:get("ca_setup", "map") then map_403_200blank_delete() end
            local wait_time = attempts <= 4 
            and (60 * (2 ^ (attempts - 1))) -- 1st: 60sec, 2nd: 120sec, 3rd: 240sec, 4th: 480sec
            or 480 -- 5th and beyond: 480sec
        
            return handle_retry("403", wait_time)

        else
            local errorMessage = code or "URL unreachable"
            log_message("Failed to retrieve map rules: " .. errorMessage)

            if attempts <= 999 then
                log_message(attempts .. "th retry attempt is waiting...")
                if not uci:get("ca_setup", "map", "dmr") then interface_down("wanmap") end
                local wait_time = attempts <= 4 
                and (60 * (2 ^ (attempts - 1))) -- 1st: 60sec, 2nd: 120sec, 3rd: 240sec, 4th: 480sec
                or 480 -- 5th and beyond: 480sec
          
                log_message("Retrying in " .. wait_time .. " seconds.")
                os.execute("sleep " .. wait_time)
                return false
            end

            log_message("All retries have failed.")
            if not uci:get("ca_setup", "map", "dmr") then
                log_message("Failed to retrieve map rules. Terminating OCN_virtualconnect operation")
                map_error_recovery(from_boot)
            else
                log_message("Failed to retrieve new map rule data, but continuing OCN_virtualconnect operation with previously obtained data")
            end
            return true
        end
    end

    while not try_fetch() do end
    check_and_ifup_wanmap()
end


-- Function to split wan_ipv6 into sections --
local function split_ipv6(wan_ipv6)
    local ipv6 = ip.IPv6(wan_ipv6)
    if not ipv6 then
        return {} -- Return empty table if invalid
    end
    
    local addr_str = ipv6:string()
    local sections = {}
    
    -- Split by colon and collect non-empty parts
    for section in addr_str:gmatch("[^:]+") do
        table.insert(sections, section)
    end
    
    return sections
end


-- Simplified find_matching_fmr function using improved is_match
local function find_matching_fmr_subnet(ipv6_str, fmr)
    local ipv6 = ip.IPv6(ipv6_str)
    if not ipv6 then
        log_message("Invalid IPv6 address: " .. tostring(ipv6_str))
        return nil
    end
    
    for _, entry in ipairs(fmr) do
        local prefix_addr, prefix_len = entry.ipv6:match("([^/]+)/(%d+)")
        if prefix_addr and prefix_len then
            local prefix = ip.IPv6(prefix_addr, tonumber(prefix_len))
            if prefix and prefix:contains(ipv6) then
                log_message("Match found for FMR entry")
                return entry
            end
        end
    end
    return nil
end


-- Function to output map config with Subnet --
local function get_mapconfig(wan_ipv6, ipv6_56, ipv6_fixlen, from_boot)
    local sections = split_ipv6(wan_ipv6)
    local wan32_ipv6, wan40_ipv6 = wan32_40(wan_ipv6)
    local endmr = uci:get("ca_setup", "map", "dmr")
    local peeraddr = decryptedData(endmr)
    local enfmrStr = uci:get("ca_setup", "map", "fmr")
    local fmr_json = decryptedData(enfmrStr)
    local fmr = json.parse(fmr_json)
    local matching_fmr = find_matching_fmr_subnet(wan40_ipv6, fmr) or find_matching_fmr_subnet(wan32_ipv6, fmr)

    if matching_fmr then
        local ipv6_prefix, ipv6_prefix_length = matching_fmr.ipv6:match("^(.-)/(%d+)$")
        local ipv4_prefix, ipv4_prefix_length = matching_fmr.ipv4:match("^(.-)/(%d+)$")
        local ealen = matching_fmr.ea_length
        local offset = matching_fmr.psid_offset
        local psidlen = ealen - (32 - ipv4_prefix_length)
        return peeraddr, ipv4_prefix, ipv4_prefix_length, ipv6_prefix, ipv6_prefix_length, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6
    else
        report_operation(manufacturer_code, callback, 2, 0, id)
        log_message("No matching FMR entry found.")
        map_error_recovery(from_boot)
        return
    end
end


-- Function to output map config for OCN --
local function get_mapconfig_ocn(wan_ipv6, ipv6_56, ipv6_fixlen, from_boot)
    local sections = split_ipv6(wan_ipv6)
    local wan32_ipv6, wan40_ipv6 = wan32_40(wan_ipv6)
    local enfmrStr = uci:get("ca_setup", "map", "fmr")
    local fmr_json = decryptedData(enfmrStr)
    local fmr = json.parse(fmr_json)
    local matching_fmr = find_matching_fmr_subnet(wan40_ipv6, fmr) or find_matching_fmr_subnet(wan32_ipv6, fmr)

    if matching_fmr then
        local peeraddr = matching_fmr.br_ipv6 -- OCN does not have dmr registration and is stored for each address
        local ipv6_prefix, ipv6_prefix_length = matching_fmr.ipv6:match("^(.-)/(%d+)$")
        local ipv4_prefix, ipv4_prefix_length = matching_fmr.ipv4:match("^(.-)/(%d+)$")
        local ealen = matching_fmr.ea_length
        local offset = matching_fmr.psid_offset
        local psidlen = ealen - (32 - ipv4_prefix_length)
        return peeraddr, ipv4_prefix, ipv4_prefix_length, ipv6_prefix, ipv6_prefix_length, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6
    else
        log_message("No matching FMR entry found.")
        map_error_recovery(from_boot)
        return
    end
end


-- Rule check
local function rule_param(mode, from_boot)
    local enParam
    if VNE == "v6_plus" or VNE == "ipv6_option" then
        enParam = uci:get("ca_setup", "getmap", "param1")
        local manufacturer_code = decryptedData(enParam)
        auto_fetch_data(manufacturer_code, from_boot)
    elseif VNE == "OCN_virtualconnect" then
        enParam = uci:get("ca_setup", "getmap", "param2")
        local manufacturer_code = decryptedData(enParam)
        auto_fetch_data_ocn(manufacturer_code, mode, from_boot)
    else
        error("N/A: " .. (VNE or "nil"))
    end
end

-- Shared DHCP LAN settings for MAP-E/DS-Lite/IPIP
local function apply_dhcp_lan_settings(ipv6_fixlen)

    -- DHCP LAN settings
    uci:set("dhcp", "lan", "dhcp")
    uci:set("dhcp", "lan", "interface", "lan")
    uci:set("dhcp", "lan", "ignore", "0")

    if qsdk == 12.2 then
        ----------------------------------------------------------------
        -- QSDK 12.2 (OpenWrt 19.07)
        -- DO NOT CHANGE ANYTHING — proven stable
        ----------------------------------------------------------------
        if ipv6_fixlen == 64 then
            -- Pure RA case (no delegated prefix)
            uci:set("dhcp", "lan", "ra_management", "2")
            uci:set("dhcp", "lan", "dhcpv6", "relay")
            uci:set("dhcp", "lan", "ra", "relay")

        elseif ipv6_fixlen == 60 then
            -- Behind HGW with RA and DHCPv6-PD by delegated prefix
            uci:set("dhcp", "lan", "ra_management", "1")
            uci:set("dhcp", "lan", "ra_default", "1")
            uci:set("dhcp", "lan", "dhcpv6", "server")
            uci:set("dhcp", "lan", "ra", "server")

        else
            -- Direct DHCPv6-PD from ISP (no HGW)
            uci:set("dhcp", "lan", "ra_management", "1")
            uci:set("dhcp", "lan", "dhcpv6", "server")
            uci:set("dhcp", "lan", "ra", "server")
        end

        uci:set("dhcp", "lan", "ndp", "relay")
        uci:set("dhcp", "lan", "force", "1")

    else
        ----------------------------------------------------------------
        -- QSDK 12.5+ (OpenWrt 23.05)
        -- Windows-stable, NTT-aligned
        ----------------------------------------------------------------

        -- Always start with cleanup to avoid sticky mode transitions
        uci:delete("dhcp", "lan", "ra_flags")
        uci:delete("dhcp", "lan", "ra_management")
        uci:delete("dhcp", "lan", "ra_other")
        uci:delete("dhcp", "lan", "ra_dns")
        uci:delete("dhcp", "lan", "ra_default")
        uci:delete("dhcp", "lan", "ra_slaac")

        if ipv6_fixlen == 64 then
            -- /64 RA-only on-link (NTT): odhcpd relay
            uci:set("dhcp", "lan", "ra", "relay")
            uci:set("dhcp", "lan", "dhcpv6", "relay")
            uci:set("dhcp", "lan", "ndp", "relay")
            uci:set("dhcp", "lan", "ra_flags", "other-config")
            uci:set("dhcp", "lan", "ra_management", "0")
            uci:set("dhcp", "lan", "ra_other", "1")
            uci:set("dhcp", "lan", "ra_dns", "1")
            uci:set("dhcp", "lan", "force", "1")
            uci:delete("dhcp", "lan", "dns")
        else
            -- /56 or /60 PD routed
            uci:set("dhcp", "lan", "ra", "server")
            uci:set("dhcp", "lan", "dhcpv6", "server")
            uci:set("dhcp", "lan", "ndp", "disabled")
            uci:set("dhcp", "lan", "ra_slaac", "1")
            uci:set("dhcp", "lan", "ra_management", "0")
            uci:set("dhcp", "lan", "ra_other", "1")
            uci:set("dhcp", "lan", "ra_default", "1")
            uci:set("dhcp", "lan", "ra_flags", "none")
            uci:set("dhcp", "lan", "force", "1")
            uci:set("dhcp", "lan", "ra_dns", "1")
        end
    end
end

local function restart_odhcpd_for_ra64(ipv6_fixlen)
    if ipv6_fixlen ~= 64 then
        return
    end

    local file = io.open("/etc/init.d/odhcpd", "r")
    if not file then
        log_message("odhcpd restart skipped: service not found")
        return
    end
    file:close()
    os.execute("/etc/init.d/odhcpd restart")
    log_message("odhcpd restarted for /64 RA relay")
end


local function configure_wan6_network_settings(ipv6_fixlen, ipv6_56, ifaceid)
    local normalized_prefix56 = normalize_ipv6_prefix(ipv6_56)

    if ifaceid and ifaceid ~= "" then
        uci:set("network", "wan6", "ifaceid", ifaceid)
    end
    uci:set("network", "wan6", "proto", "dhcpv6")
    uci:set("network", "wan6", "reqaddress", "try")
    if ipv6_fixlen == 64 and qsdk >= 12.5 then
        uci:set("network", "wan6", "reqprefix", "auto")
        uci:delete("network", "wan6", "norelease")
        uci:delete("network", "wan6", "ip6prefix")
    elseif ipv6_fixlen == 64 then
        uci:set("network", "wan6", "reqprefix", "auto")
        uci:delete("network", "wan6", "norelease")
        uci:set("network", "wan6", "ip6prefix", normalized_prefix56 .. "/" .. ipv6_fixlen)
    else
        uci:set("network", "wan6", "reqprefix", "auto")
        uci:delete("network", "wan6", "norelease")
        uci:delete("network", "wan6", "ip6prefix")
    end
end

local function setup_ra_route_boot_hook()
    local script_path = "/usr/sbin/auto-ipoe-ra-route.sh"
    local init_path = "/etc/init.d/auto-ipoe-ra-route"

    local script = [[#!/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
WAN_DEV=$(ubus call network.interface.wan6 status | jsonfilter -e '@.l3_device' 2>/dev/null)
[ -z "$WAN_DEV" ] && WAN_DEV=eth0
LAN_DEV=$(uci -q get network.lan.device || echo br-lan)

get_prefix_from_addr() {
    local addr="$1"
    [ -z "$addr" ] && return 1
    addr=${addr%%/*}
    IFS=: read -r h1 h2 h3 h4 _ <<EOF
$addr
EOF
    [ -n "$h1" ] && [ -n "$h2" ] && [ -n "$h3" ] && [ -n "$h4" ] || return 1
    PREFIX="${h1}:${h2}:${h3}:${h4}::/64"
    return 0
}

find_prefix() {
    local p addr
    p=$(ip -6 route show dev "$WAN_DEV" 2>/dev/null | \
        sed -n 's/^\([0-9A-Fa-f:][0-9A-Fa-f:]*::\/64\).*/\1/p' | \
        grep -v '^fe80' | head -n1)
    if [ -n "$p" ]; then
        PREFIX="$p"
        return 0
    fi
    addr=$(ip -6 addr show dev "$WAN_DEV" scope global 2>/dev/null | \
        sed -n 's/.*inet6 \([^ ]*\).*/\1/p' | head -n1)
    get_prefix_from_addr "$addr"
}

i=1
while [ $i -le 30 ]; do
    PREFIX=""
    if find_prefix; then
        if ip -6 route replace "$PREFIX" dev "$LAN_DEV" metric 128 2>/dev/null; then
            logger -t auto-ipoe "RA route ensured: $PREFIX via $LAN_DEV"
            exit 0
        else
            logger -t auto-ipoe "RA route add failed: $PREFIX via $LAN_DEV"
        fi
    elif [ $i -eq 1 ] || [ $i -eq 30 ]; then
        logger -t auto-ipoe "RA route wait: prefix not found yet (WAN_DEV=$WAN_DEV)"
    fi
    i=$((i + 1))
    sleep 2
done
logger -t auto-ipoe "RA route not added: prefix not found or route add failed"
exit 1
]]

    local file = io.open(script_path, "w")
    if file then
        file:write(script)
        file:close()
        os.execute("chmod +x " .. script_path)
    end

    local init_script = [[#!/bin/sh /etc/rc.common
START=99
STOP=10

start() {
    ]] .. script_path .. [[ &
}

stop() {
    :
}
]]

    local init_file = io.open(init_path, "w")
    if init_file then
        init_file:write(init_script)
        init_file:close()
        os.execute("chmod +x " .. init_path)
        os.execute(init_path .. " enable 2>/dev/null")
    end
end

local function setup_auto_ipoe_one_shot()
    local init_path = "/etc/init.d/auto-ipoe-once"
    local flag_path = "/etc/auto-ipoe-once"
    local lua_bin = "/usr/bin/lua"
    local map_script = "/usr/lib/lua/mapv6.lua"
    local init_script = [[#!/bin/sh /etc/rc.common
START=15

start() {
    [ -f ]] .. flag_path .. [[ ] || exit 0
    rm -f ]] .. flag_path .. [[
    ]] .. lua_bin .. [[ ]] .. map_script .. [[ --from-boot &
    /etc/init.d/auto-ipoe-once disable 2>/dev/null
    rm -f ]] .. init_path .. [[ /etc/rc.d/S15auto-ipoe-once
}
]]

    local f = io.open(init_path, "w")
    if not f then
        log_message("Failed to write one-shot auto-ipoe init script: " .. init_path)
        return false
    end
    f:write(init_script)
    f:close()
    os.execute("chmod +x " .. init_path)
    os.execute(init_path .. " enable 2>/dev/null")
    os.execute("touch " .. flag_path)
    log_message("One-shot auto-ipoe init hook installed for next boot")
    return true
end

local function configure_lan_onlink_route(ipv6_fixlen)
    local section = "auto_ipoe_lan_onlink_64"
    uci:delete("network", section)

    if ipv6_fixlen ~= 64 then
        return
    end

    if not (qsdk and qsdk >= 12.5) then
        log_message("Skipping LAN on-link /64 route on QSDK <12.5")
        return
    end

    local prefix_64 = extract_ipv6_64(wan_ipv6 or "")
    if (not prefix_64 or prefix_64 == "") and ipv6Prefix and ipv6Prefix ~= "not found" then
        prefix_64 = extract_ipv6_64(ipv6Prefix)
    end

    if not prefix_64 or prefix_64 == "" then
        log_message("Skipping LAN on-link /64 route: prefix not found")
        return
    end

    uci:section("network", "route6", section, {
        interface = "lan",
        target = prefix_64 .. "/64",
        metric = "128"
    })
    log_message("LAN on-link /64 route added: " .. prefix_64 .. "/64 metric 128")

    if qsdk >= 12.5 then
        -- For QSDK 12.5+ /64 RA-only: keep LAN without a global IPv6 address
        uci:delete("network", "lan", "ip6addr")
        log_message("LAN static IPv6 address cleared for /64 RA-only")
    end
end

local function configure_wan6_dhcp_settings(ipv6_fixlen)
    uci:set("dhcp", "wan6", "dhcp")
    uci:set("dhcp", "wan6", "interface", "wan6")
    uci:set("dhcp", "wan6", "master", "1")
    if ipv6_fixlen == 64 and qsdk ~= 12.2 then
        uci:set("dhcp", "wan6", "ignore", "0")
    else
        uci:set("dhcp", "wan6", "ignore", "1")
    end
    uci:set("dhcp", "wan6", "dhcpv6", "relay")
    uci:set("dhcp", "wan6", "ra", "relay")
    uci:set("dhcp", "wan6", "ndp", "relay")
end

local function sync_ecm_acceleration_engine()
    local target_engine = uci:get("ca_setup", "getmap", "ecm")
    if target_engine == nil then
        return
    end

    target_engine = tostring(target_engine):match("^%s*(.-)%s*$")
    if target_engine == "" then
        return
    end

    local current_engine = uci:get("ecm", "global", "acceleration_engine")
    if current_engine == target_engine then
        return
    end

    uci:set("ecm", "global", "acceleration_engine", target_engine)
    uci:commit("ecm")
    os.execute("if [ -x /etc/init.d/qca-nss-ecm ]; then /etc/init.d/qca-nss-ecm restart; fi")
end


-- map-e v6 plus connection configuration function
local function configure_mape_connection(peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, under_router)
    sync_ecm_acceleration_engine()

    apply_dhcp_lan_settings(ipv6_fixlen)

    -- DHCP WAN6 settings
    configure_wan6_dhcp_settings(ipv6_fixlen)
    uci:commit("dhcp")  
    restart_odhcpd_for_ra64(ipv6_fixlen)

    -- WAN settings - keep active if needed
    if under_router == 3 then
        uci:set("network", "wan", "auto", "1")  -- Keep WAN active
    else
        uci:set("network", "wan", "auto", "0")  -- Disable WAN
    end
    -- WAN6 settings
    configure_wan6_network_settings(ipv6_fixlen, ipv6_56)
   
   
    -- WANMAP settings
    uci:section("network", "interface", "wanmap", {
        proto = "map",
        maptype = "map-e",
        peeraddr = peeraddr,
        ipaddr = ipv4_prefix,
        ip4prefixlen = ipv4_prefixlen,
        ip6prefix = ipv6_prefix,
        ip6prefixlen = ipv6_prefixlen,
        ealen = ealen,
        psidlen = psidlen,
        offset = offset,
        legacymap = "1",
        mtu = "1460",
        tunlink= "wan6",
        encaplimit = "ignore"
    })

    -- LAN settings
    uci:delete("network", "globals", "ula_prefix") 
    if ipv6_fixlen == 64 and qsdk >= 12.5 then
        uci:set("network", "lan", "ip6assign", "0")
    elseif ipv6_fixlen == 60 then
        uci:set("network", "lan", "ip6assign", "64")  -- For 60, use 64
    else
        uci:set("network", "lan", "ip6assign", ipv6_fixlen)  -- For 56 or 64, use the actual value
    end
    configure_lan_onlink_route(ipv6_fixlen)
    uci:commit("network") 

    -- Firewall settings - keep WAN in zone 1 if needed
    if under_router == 3 then
        uci:set_list("firewall", "@zone[1]", "network", {"wan", "wan6", "wanmap"})
    else
        uci:delete("firewall", "@zone[1]", "network", "wan")
        uci:set_list("firewall", "@zone[1]", "network", {"wan6", "wanmap"})
    end
    ensure_quic_block_firewall_rule()
    uci:commit("firewall")

end


-- ds-lite connection configuration function
local function configure_dslite_connection(gw_aftr, ipv6_fixlen, ipv6_56, under_router)
    sync_ecm_acceleration_engine()

    apply_dhcp_lan_settings(ipv6_fixlen)

    -- WAN settings - keep active if needed
    if under_router == 3 then
        uci:set("network", "wan", "auto", "1")  -- Keep WAN active
    else
        uci:set("network", "wan", "auto", "0")  -- Disable WAN
    end
    -- WAN6 settings
    configure_wan6_network_settings(ipv6_fixlen, ipv6_56)


    -- Configure DS-Lite interface
    uci:section("network", "interface", "dslite", {
        proto = 'dslite',
        peeraddr = gw_aftr, 
        tunlink = 'wan6',
        mtu = '1460',
        encaplimit = 'ignore'
    })
    
    -- DHCP related settings
    configure_wan6_dhcp_settings(ipv6_fixlen)
    uci:commit("dhcp")
    restart_odhcpd_for_ra64(ipv6_fixlen)

    os.execute([[sed -i -e 's/mtu:-1280/mtu:-1460/g' /lib/netifd/proto/dslite.sh]])

    -- LAN settings
    uci:delete("network", "globals", "ula_prefix") 
    if ipv6_fixlen == 64 and qsdk >= 12.5 then
        uci:set("network", "lan", "ip6assign", "0")
    elseif ipv6_fixlen == 60 then
        uci:set("network", "lan", "ip6assign", "64")  -- For 60, use 64
    else
        uci:set("network", "lan", "ip6assign", ipv6_fixlen)  -- For 56 or 64, use the actual value
    end
    configure_lan_onlink_route(ipv6_fixlen)
    uci:commit("network") 

     -- Firewall settings - keep WAN in zone 1 if needed
    if under_router == 3 then
        uci:set_list("firewall", "@zone[1]", "network", {"wan", "wan6", "dslite"})
    else
        uci:set_list("firewall", "@zone[1]", "network", {"wan6", "dslite"})
    end
    ensure_quic_block_firewall_rule()
    uci:commit("firewall")

end


-- Function to extract IPv6 interface ID from an IPv6 local address
local function extract_ipv6_ifaceid(ipv6_local)
    -- Default value if extraction fails
    local ipv6_ifaceid = "::1"
    
    if ipv6_local and ipv6_local ~= "nil" then
        -- Extract everything after the 4th colon (the /64 prefix boundary)
        local prefix, suffix = ipv6_local:match("^([^:]+:[^:]+:[^:]+:[^:]+:)(.*)")
        if suffix then
            -- If the suffix starts with "0:", strip it to match expected format
            suffix = suffix:gsub("^0:", "")
            ipv6_ifaceid = "::" .. suffix
        end
    end
    
    return ipv6_ifaceid
end

-- ipip connection configuration function
local function configure_ipip_connection(ipv4_addr, ipv6_local, ipv6_remote, ipv6_ifaceid, ipv6_fixlen, ipv6_56)
    log_message("Configuring IPIP connection...")
    log_message("IPv4 Address: " .. ipv4_addr)
    log_message("IPv6 Local: " .. ipv6_local)
    log_message("IPv6 Remote: " .. ipv6_remote)
    log_message("IPv6 Interface ID: " .. ipv6_ifaceid)

    sync_ecm_acceleration_engine()
    
    -- IPIP6 interface configuration
    uci:section("network", "interface", "ipip6", {
        proto = 'ipip6',
        peeraddr = ipv6_remote,
        ip4ifaddr = ipv4_addr,
        ip6addr = ipv6_local,
        tunlink = 'wan6',
        encaplimit = 'ignore',
        mtu = '1460',
        peerdns = '0'
    })
    

    apply_dhcp_lan_settings(ipv6_fixlen)


    -- WAN6/LAN settings - use /64 prefix with extracted interface ID
    configure_wan6_network_settings(ipv6_fixlen, ipv6_56, ipv6_ifaceid)

    uci:set("network", "lan", "ip6ifaceid", ipv6_ifaceid)
    if ipv6_fixlen == 64 and qsdk >= 12.5 then
        uci:set("network", "lan", "ip6assign", "0")
    else
        uci:set("network", "lan", "ip6assign", "64")
    end
    configure_lan_onlink_route(ipv6_fixlen)
    uci:delete("network", "globals", "ula_prefix")
    uci:commit("network")
    
    -- Firewall settings
    uci:set_list("firewall", "@zone[1]", "network", {"wan", "wan6", "ipip6"})
    ensure_quic_block_firewall_rule()
    uci:commit("firewall")
    
    -- DHCP related settings
    configure_wan6_dhcp_settings(ipv6_fixlen)
    uci:commit("dhcp")
    restart_odhcpd_for_ra64(ipv6_fixlen)
    
    log_message("IPIP configuration applied")
    return true
end


-- Shared helpers for returning WAN to DHCP and clearing map/dslite config
local function delete_config(config, section, option, value)
    if option then
        uci:delete(config, section, option)
    else
        uci:delete(config, section)
    end
    if value then
        for _, v in ipairs(value) do
            uci:delete(config, section, option, v)
        end
    end
end

reset_wan_to_dhcp = function(drop_map_state)
    -- Check if map, dslite, map6ra settings exist
    local mapExists = uci:get("network", "wanmap") or uci:get("network", "map6ra") or uci:get("network", "dslite") or uci:get("network", "ipip6")
    local map_state_exists = uci:get("ca_setup", "map") ~= nil

    local function remove_auto_ipoe_sysctl()
        if not sysctl_config or sysctl_config == "" then
            return false
        end
        local ok, err = os.remove(sysctl_config)
        if ok then
            log_message("Removed auto-ipoe sysctl config: " .. sysctl_config)
            return true
        end
        if err and not tostring(err):lower():match("no such file") then
            log_message("Failed to remove auto-ipoe sysctl config: " .. sysctl_config .. " (" .. tostring(err) .. ")")
        end
        return false
    end

    local function normalize_dhcp_auto()
        -- Apply DHCP auto defaults for WAN/WAN6 and LAN DHCPv6/RA
        uci:set("network", "wan", "proto", "dhcp")
        uci:set("network", "wan6", "proto", "dhcpv6")
        uci:delete("network", "wan6", "reqaddress")
        uci:delete("network", "wan6", "reqprefix")
        uci:delete("network", "wan6", "ip6prefix")
        uci:delete("network", "wan6", "norelease")
        uci:set("network", "lan", "ip6assign", "60")
        uci:set("network", "globals", "ula_prefix", "auto")

        uci:set("dhcp", "lan", "interface", "lan")
        uci:set("dhcp", "lan", "dhcpv6", "server")
        uci:set("dhcp", "lan", "ra", "server")
        uci:set("dhcp", "lan", "ra_slaac", "1")
        uci:delete("dhcp", "lan", "ra_management")
        uci:delete("dhcp", "lan", "ra_other")
        uci:delete("dhcp", "lan", "ra_dns")
        uci:delete("dhcp", "lan", "ndp")
        uci:delete("dhcp", "lan", "ra_flags")
        uci:set_list("dhcp", "lan", "ra_flags", {"other-config"})

        if uci:get("dhcp", "wan6") then
            uci:delete("dhcp", "wan6")
        end

        uci:set_list("firewall", "@zone[1]", "network", {"wan", "wan6"})
    end

    if mapExists then
        -- If it exists, delete the specified configuration
        delete_config("dhcp", "lan", "ndp")
        delete_config("dhcp", "lan", "ra_management")
        delete_config("dhcp", "lan", "force")
        delete_config("network", "wan", "auto")
        delete_config("network", "wan6", "reqaddress")
        delete_config("network", "wan6", "reqprefix")
        delete_config("network", "wan6", "ip6prefix")
        delete_config("network", "lan", "ip6assign")
        delete_config("network", "auto_ipoe_lan_onlink_64")
        delete_config("network", "map6ra")
        delete_config("network", "wanmap")
        delete_config("network", "dslite")
        delete_config("network", "ipip6")
        delete_config("firewall", "@zone[1]", "network", {"wanmap", "map6ra", "dslite", "ipip6"})

        -- Apply DHCP related settings
        normalize_dhcp_auto()
        
        -- Delete map log when requested
        if drop_map_state then
            uci:delete("ca_setup", "map")
            map_state_exists = false
            remove_quic_block_firewall_rule()
            remove_dscp_zero_nft()
        end
        
        -- Commit the settings
        uci:commit("dhcp")
        uci:commit("network")
        uci:commit("firewall")
        if drop_map_state then
            uci:commit("ca_setup")
        end
        remove_auto_ipoe_sysctl()

        return true
    end

    if drop_map_state then
        normalize_dhcp_auto()
        uci:delete("ca_setup", "map")
        remove_quic_block_firewall_rule()
        uci:commit("dhcp")
        uci:commit("network")
        uci:commit("firewall")
        if map_state_exists then
            uci:commit("ca_setup")
        end
        remove_dscp_zero_nft()
        remove_auto_ipoe_sysctl()
    end

    return false
end


-- clean wan function for when there is a possibility of switching from dslite to map --
local function clean_wan_configuration()
    reset_wan_to_dhcp(false)
end


-- UCI configuration function to revert from map or dslite state to DHCP auto --
local function apply_dhcp_configuration()
    if reset_wan_to_dhcp(true) then
        network_restart_handler("DHCP auto configuration", 0)
        if not (qsdk and qsdk >= 12.5) then
            os.execute("/etc/init.d/firewall restart")
        end
    else
        log_message("Currently operating with DHCP auto configuration, no changes required.")
    end
end


-- Recovery routine when WAN STATUS is unknown
-- Temporarily start WAN IPv4 DHCP to investigate the status. Also, collect router/HGW flags.
local function recovery_wan()
    -- Check the operational status of the WAN interface
    local handle, err = io.popen("ubus call network.interface.wan status")
    if not handle then
        log_message("Error running command: " .. err)
        return
    end

    local status = handle:read("*a")
    handle:close()

    -- "up": false、"pending": true、"available": trueを確認
    if status:find('"up": false') then
        -- Bring up the WAN interface
        log_message("Bringing WAN IPv4 interface up...")
        interface_up("wan")

        -- Wait for 30 seconds
        log_message("Waiting for 30 seconds to pick up IPv4 address...")
        os.execute("sleep 30")

        -- Re-execute the routine to check for upstream routers and HGW (obtain flags)
        check_under_router(wan_interface, wan6_interface)  -- Check if the first hop is a private IP
        check_ntt_hgw()       -- Check for the presence of NTT HGW

        -- Bring down the WAN interface
        log_message("Bringing WAN interface down...")
        interface_down("wan")

        -- Flow to IPoE registration change routine
        samewan = "N"
    else
        log_message("WAN interface is already up and running.")
    end
end


local function update_sysctl_conf(path, updates)
    local content = ""
    local file = io.open(path, "r")
    if file then
        content = file:read("*a") or ""
        file:close()
    end

    local lines = {}
    local seen = {}
    if content ~= "" then
        for line in (content .. "\n"):gmatch("([^\n]*)\n") do
            local key = line:match("^%s*([%w%._-]+)%s*=")
            if key and updates[key] then
                line = key .. "=" .. updates[key]
                seen[key] = true
            end
            table.insert(lines, line)
        end
    end

    local ordered_keys = {}
    for key in pairs(updates) do
        table.insert(ordered_keys, key)
    end
    table.sort(ordered_keys)
    for _, key in ipairs(ordered_keys) do
        if not seen[key] then
            table.insert(lines, key .. "=" .. updates[key])
        end
    end

    local out = io.open(path, "w")
    if not out then
        return false
    end
    out:write(table.concat(lines, "\n"))
    out:write("\n")
    out:close()
    return true
end

-- Function to adjust sysctl settings
local function tune_sysctl(ipv6_fixlen, under_router)
    -- Adjust sysctl settings based on IPv6 prefix length and router mode
    local settings = {}

    -- Add nf_conntrack timeouts (always set)
    table.insert(settings, "net.netfilter.nf_conntrack_tcp_timeout_established=3600")
    table.insert(settings, "net.netfilter.nf_conntrack_tcp_timeout_time_wait=120")
    table.insert(settings, "net.netfilter.nf_conntrack_udp_timeout=180")
    table.insert(settings, "net.netfilter.nf_conntrack_udp_timeout_stream=180")
    table.insert(settings, "net.netfilter.nf_conntrack_icmp_timeout=60") 
    table.insert(settings, "net.netfilter.nf_conntrack_generic_timeout=60")

    -- Skip IPv6 settings when under another router (HGW mode)
    local skip_ipv6 = (under_router == 1) or (under_router == 2 and ipv6_fixlen ~= 64)
    if not skip_ipv6 then

        if qsdk == 12.2 then

            -- Common settings for all prefix lengths
            -- Always accept Router Advertisements even with forwarding enabled
            table.insert(settings, "net.ipv6.conf.all.accept_ra=2")
            table.insert(settings, "net.ipv6.conf.default.accept_ra=2")
            table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".accept_ra=2")
            table.insert(settings, "net.ipv6.conf.br-lan.accept_ra=0")
            
            -- Always enable IPv6 forwarding
            table.insert(settings, "net.ipv6.conf.all.forwarding=1")
            table.insert(settings, "net.ipv6.conf.default.forwarding=1")
            table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".forwarding=1")
            table.insert(settings, "net.ipv6.conf.br-lan.forwarding=1")
            
            -- Only proxy_ndp varies by prefix length
            if ipv6_fixlen == 64 then
                -- Enable NDP proxy only in pure RA environments (/64)
                -- This is needed for IPv6 RA relay functionality
                table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".proxy_ndp=1")
                table.insert(settings, "net.ipv6.conf.br-lan.proxy_ndp=0")
            else
                -- Disable NDP proxy for DHCPv6-PD environments (/56 or /60)
                table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".proxy_ndp=0")
            end
            
            -- Always disable proxy_ndp on LAN
            table.insert(settings, "net.ipv6.conf.br-lan.proxy_ndp=0")

        else

            -- Always safe on WAN: accept RA even with forwarding
            table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".accept_ra=2")
            table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".autoconf=1")
            table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".accept_ra_pinfo=1")
            table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".accept_ra_defrtr=1")

            -- Routing on (both models)
            table.insert(settings, "net.ipv6.conf.all.forwarding=1")
            table.insert(settings, "net.ipv6.conf.default.forwarding=1")
            table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".forwarding=1")
            table.insert(settings, "net.ipv6.conf.br-lan.forwarding=1")

            if ipv6_fixlen == 64 then
                ------------------------------------------------------------------
                -- /64 RA relay model: autoconf ON
                ------------------------------------------------------------------
                table.insert(settings, "net.ipv6.conf.br-lan.accept_ra=0")
                table.insert(settings, "net.ipv6.conf.br-lan.autoconf=1")
                table.insert(settings, "net.ipv6.conf.all.accept_ra=2")
                table.insert(settings, "net.ipv6.conf.all.autoconf=1")
                table.insert(settings, "net.ipv6.conf.default.accept_ra=2")
                table.insert(settings, "net.ipv6.conf.default.autoconf=1")
                -- Enable kernel proxy_ndp for NDP relay on /64 (WAN-only)
                table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".proxy_ndp=1")
                table.insert(settings, "net.ipv6.conf.br-lan.proxy_ndp=0")

            else
                ------------------------------------------------------------------
                -- PD routed model (/56, /60, etc): proxy NDP OFF
                ------------------------------------------------------------------
                table.insert(settings, "net.ipv6.conf.br-lan.accept_ra=0")
                table.insert(settings, "net.ipv6.conf.br-lan.autoconf=0")
                table.insert(settings, "net.ipv6.conf.default.accept_ra=0")
                table.insert(settings, "net.ipv6.conf.default.autoconf=0")
                table.insert(settings, "net.ipv6.conf." .. wan6_interface .. ".proxy_ndp=0")
                table.insert(settings, "net.ipv6.conf.br-lan.proxy_ndp=0")

            end

        end

    end

    -- Keep sysctl output deterministic for diffability
    table.sort(settings)

    local file = io.open(sysctl_config, "w")
    if file then
        for _, setting in ipairs(settings) do
            file:write(setting .. "\n")
        end
        file:close()
        if qsdk == 12.2 then
            os.execute("sysctl -p " .. sysctl_config)
            log_message("Adjusted sysctl settings. Changes applied immediately.")
        else
            log_message("Adjusted sysctl settings. Reboot required for changes to take effect.")
        end
    else
        log_message("Failed to write sysctl configuration file.")
    end
end

-- clean wan & ca_setup configuration and reboot
local function clean_wan_and_reboot()
        log_message("Cleaning WAN & CA configuration...")
        clean_wan_configuration()
        uci:delete("ca_setup", "map")
        uci:commit("ca_setup")
        log_message("rebooting the router...")
        script_lock_disable()
        save_logs_to_persistent_storage()
        os.execute("sleep 5")
        reboot_system()
end

-- Reboot after applying a new MAP-E/DS-Lite setup
local function reboot_after_new_setup(setup_type, from_boot)
    if not (from_boot == true) then
        log_message("New " .. (setup_type or "network") .. " setup applied (no reboot for normal run)")
        schedule_next_run(from_boot)
        script_lock_disable()
        save_logs_to_persistent_storage()
        return
    end

    log_message("Rebooting after new " .. (setup_type or "network") .. " setup (from boot)...")
    schedule_next_run(from_boot)
    script_lock_disable()
    save_logs_to_persistent_storage()
    os.execute("sleep 5")
    reboot_system()
    os.exit(0)
end

-- Check if there is no difference from the previous WAN6 state.
local function samewancheckfunc(cur_state)
    local last_sig = uci:get("ca_setup", "map", "cur_sig")
    local cur_sig = cur_state and cur_state.sig or nil

    samewan = "N"

    if last_sig and cur_sig then
        if last_sig ~= cur_sig then
            log_message("WAN /64 state has changed: '" .. last_sig .. "' -> '" .. cur_sig .. "'.")
            clean_wan_and_reboot()
        else
            log_message("WAN /64 state has not changed.")
            samewan = "Y"
        end
        return samewan
    end

    return samewan
end


-- Function to detect and resolve IP conflicts with parent device
function check_ip_duplication()
    -- Skip check if WAN interface is nil
    if not wan_interface or wan_interface == "" then
        log_message("Skipping IP conflict check - WAN interface is not defined")
        return false
    end
    
    log_message("Checking for subnet conflicts between WAN and LAN...")
    
    -- Get the current LAN IP and subnet of this router
    local lan_ip = uci:get("network", "lan", "ipaddr") or "192.168.1.1"
    local lan_netmask = uci:get("network", "lan", "netmask") or "255.255.255.0"
    local lan_cidr = ip.IPv4(lan_ip, lan_netmask)
    
    if not lan_cidr then
        log_message("Error parsing LAN IP configuration")
        return false
    end
    
    log_message("Current LAN subnet: " .. lan_cidr:string())
    
    -- Get WAN IP address assigned to interface
    local handle = io.popen("ip addr show dev " .. wan_interface .. " | grep 'inet ' | awk '{print $2}'")
    local wan_cidr_str = handle:read("*a"):gsub("%s+$", "")
    handle:close()
    
    -- If no WAN IP found, no conflict possible
    if not wan_cidr_str or wan_cidr_str == "" then
        log_message("No WAN IP detected - no conflict possible")
        return false
    end
    
    -- Parse WAN IP with internal IP wrapper
    local wan_cidr = ip.IPv4(wan_cidr_str)
    if not wan_cidr then
        log_message("Error parsing WAN IP: " .. wan_cidr_str)
        return false
    end
    
    log_message("WAN IP: " .. wan_cidr:string())
    
    -- Check if WAN IP is in the same subnet as LAN
    if lan_cidr:contains(wan_cidr) or wan_cidr:contains(lan_cidr) then
        log_message("IP SUBNET CONFLICT DETECTED! WAN and LAN are in the same subnet")
        log_message("Changing LAN IP from " .. lan_ip .. " to 192.168.10.1")
        
        -- Change LAN IP in UCI configuration to a different subnet
        uci:set("network", "lan", "ipaddr", "192.168.10.1")
        uci:commit("network")
        
        log_message("Rebooting the router to apply new LAN IP...")
        script_lock_disable()
        save_logs_to_persistent_storage()
        os.execute("sleep 5")
        reboot_system()
        return true
    end
    
    -- Also check gateway IP for potential conflicts
    local gateway_handle = io.popen("ip route show | grep default | awk '{print $3}'")
    local gateway_ip = gateway_handle:read("*a"):gsub("%s+$", "")
    gateway_handle:close()
    
    if gateway_ip and gateway_ip ~= "" then
        local gateway_addr = ip.IPv4(gateway_ip)
        if gateway_addr and lan_cidr:contains(gateway_addr) then
            log_message("IP SUBNET CONFLICT DETECTED! Gateway (" .. gateway_ip .. ") is in LAN subnet")
            log_message("Changing LAN IP from " .. lan_ip .. " to 192.168.10.1")
            
            -- Change LAN IP in UCI configuration
            uci:set("network", "lan", "ipaddr", "192.168.10.1")
            uci:commit("network")
            
            log_message("Rebooting the router to apply new LAN IP...")
            script_lock_disable()
            save_logs_to_persistent_storage()
            os.execute("sleep 5")
            reboot_system()
            return true
        end
    end
    
    log_message("No IP subnet conflict detected between WAN and LAN")
    return false
end


-- Function to configure kernel DAD parameters for an interface
-- dad_transmits: Number of DAD NS packets to send (default 1, RFC 4862 recommends 1)
-- Setting to 0 disables DAD entirely (not recommended)
-- Higher values increase detection reliability but take longer
local function configure_dad_parameters(interface_name, dad_transmits)
    local dev = get_ifname(interface_name)
    if not dev or dev == "" then
        log_message("WARNING: Cannot configure DAD - interface not found: " .. tostring(interface_name))
        return false
    end
    
    dad_transmits = dad_transmits or 1
    
    -- Configure DAD transmit count
    local sysctl_path = "/proc/sys/net/ipv6/conf/" .. dev .. "/dad_transmits"
    local f = io.open(sysctl_path, "w")
    if f then
        f:write(tostring(dad_transmits))
        f:close()
        log_message("Set DAD transmits to " .. dad_transmits .. " for " .. dev)
    else
        -- Fallback to sysctl command
        os.execute("sysctl -w net.ipv6.conf." .. dev .. ".dad_transmits=" .. dad_transmits .. " 2>/dev/null")
    end
    
    return true
end


-- Function to verify a specific IPv6 address doesn't conflict before assigning it
-- This sends a NS probe to check if the address is already in use
local function verify_address_available(ipv6_addr, interface_name, timeout)
    timeout = timeout or 3
    local dev = get_ifname(interface_name) or interface_name
    
    log_message("Verifying address availability: " .. ipv6_addr .. " on " .. dev)
    
    -- Use ndisc6 or ping6 to probe for the address
    -- If we get a response, the address is in use
    local probe_cmd = "ping6 -c 1 -W " .. timeout .. " -I " .. dev .. " " .. ipv6_addr .. " 2>/dev/null"
    local result = os.execute(probe_cmd)
    
    if result == 0 then
        -- Got a response - address is already in use!
        log_message("WARNING: Address " .. ipv6_addr .. " is already in use on the network!")
        return false, "in_use"
    end
    
    -- No response - address appears available
    -- But we should also check local interfaces
    local local_check = sys.exec("ip -6 addr show | grep -w '" .. ipv6_addr .. "' 2>/dev/null")
    if local_check and local_check ~= "" then
        log_message("Address " .. ipv6_addr .. " is already assigned locally")
        return true, "already_local"
    end
    
    log_message("Address " .. ipv6_addr .. " appears available")
    return true, "available"
end


-- Function to check DAD status on a given interface
local function check_dad_status(interface_name, timeout_seconds, max_retries)
    timeout_seconds = timeout_seconds or 20
    max_retries = max_retries or 1
    
    local dev = get_l3_device(interface_name)
    if not dev or dev == "" then
        log_message("ERROR: Interface not found: " .. tostring(interface_name))
        return false, "interface_not_found"
    end
    log_message("Checking DAD status for interface: " .. interface_name .. " (dev: " .. dev .. ")")

    for retry = 1, max_retries do
        if retry > 1 then
            log_message("DAD check retry " .. retry .. "/" .. max_retries)
        end
        
        local deadline = os.time() + timeout_seconds
        local last_flags = ""
        local checked_addresses = {}

        while os.time() < deadline do
            local out = sys.exec("ip -j -6 addr show dev " .. dev .. " 2>/dev/null")
            local addrs = json.parse(out) or {}
            
            local has_global = false
            local has_tentative = false
            local has_dadfailed = false
            local failed_addr = nil

            -- Check all interfaces returned (handles multiple IPs)
            -- Only check GUA (Global Unicast Addresses), skip link-local and ULA
            for _, ifc in ipairs(addrs) do
                for _, addr in ipairs(ifc.addr_info or {}) do
                    -- Only process global addresses (skip link-local fe80::, ULA fc00::/fd00::)
                    if addr.scope == "global" then
                        local addr_str = addr.local_addr or addr["local"] or ""
                        local flags = table.concat(addr.flags or {}, ",")
                        
                        -- Track which GUA addresses we've seen
                        if addr_str ~= "" and not checked_addresses[addr_str] then
                            checked_addresses[addr_str] = true
                            log_message("DAD checking GUA: " .. addr_str .. " flags=" .. flags)
                        end
                        
                        has_global = true
                        last_flags = flags
                        
                        if flags:find("dadfailed") then 
                            has_dadfailed = true
                            failed_addr = addr_str
                        end
                        if flags:find("tentative") then 
                            has_tentative = true 
                        end
                    end
                end
            end

            if has_dadfailed then
                log_message("DAD FAILED on " .. interface_name .. " addr=" .. tostring(failed_addr) .. " flags=" .. last_flags)
                if retry < max_retries then
                    -- Try to clear the failed address and regenerate
                    log_message("Attempting to clear DAD-failed address and retry...")
                    if failed_addr then
                        os.execute("ip -6 addr del " .. failed_addr .. " dev " .. dev .. " 2>/dev/null")
                    end
                    os.execute("ip link set " .. dev .. " down && sleep 1 && ip link set " .. dev .. " up")
                    os.execute("sleep 3")
                    break -- Break inner loop to retry
                end
                return false, "failed"
            end
            
            if has_global and not has_tentative then
                log_message("DAD passed on " .. interface_name .. " (all global addresses verified)")
                return true, "passed"
            end

            os.execute("sleep 1")
        end
        
        -- If we got here due to timeout (not retry break), check final state
        if retry == max_retries then
            -- Final check - if we have global addresses without tentative flag, consider it passed
            local out = sys.exec("ip -j -6 addr show dev " .. dev .. " 2>/dev/null")
            local addrs = json.parse(out) or {}
            for _, ifc in ipairs(addrs) do
                for _, addr in ipairs(ifc.addr_info or {}) do
                    if addr.scope == "global" then
                        local flags = table.concat(addr.flags or {}, ",")
                        if not flags:find("tentative") and not flags:find("dadfailed") then
                            log_message("DAD check: found valid global address after timeout, considering passed")
                            return true, "passed"
                        end
                    end
                end
            end
        end
    end

    log_message("DAD check timed out after " .. timeout_seconds .. "s x " .. max_retries .. " retries on " .. interface_name)
    return true, "timeout"
end


-- Function to recover from DAD failures
local function recover_from_dad_failure(interface_name, failure_type)
    log_message("Attempting to recover from DAD failure on " .. interface_name)
    
    -- Get the physical interface name
    local dev = get_ifname(interface_name)
    if not dev then
        log_message("ERROR: Interface not found for recovery: " .. interface_name)
        return false
    end
    
    -- Record the failure in UCI for reference
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    uci:set("ca_setup", "dad_failures", "last_failure", timestamp)
    uci:set("ca_setup", "dad_failures", "interface", interface_name)
    uci:set("ca_setup", "dad_failures", "failure_type", failure_type)
    uci:commit("ca_setup")
    
    -- Only attempt recovery for actual DAD failures, not timeouts
    if failure_type == "failed" then
        -- For detected duplicates, try to generate a new interface ID
        log_message("Detected duplicate address - attempting to regenerate IPv6 address")
        
        -- Option 1: Try to regenerate the interface ID by bringing interface down/up
        interface_down(interface_name)
        os.execute("sleep 2")
        interface_up(interface_name)
        
        -- Wait a bit for the interface to come up
        os.execute("sleep 5")
        
        -- Check if DAD passes after recovery attempt
        local success, status = check_dad_status(interface_name, 5, 10)
        if success then
            log_message("DAD recovery successful for " .. interface_name)
            return true
        else
            log_message("DAD recovery failed for " .. interface_name .. " - falling back to DHCP AUTO")
            -- Fall back to DHCP auto configuration if we can't resolve the DAD issue
            clean_wan_configuration()
            apply_dhcp_configuration()
            return false
        end
    elseif failure_type == "timeout" then
        -- For timeouts, we've already waited a long time with exponential backoff
        -- so we'll just continue with the configuration
        log_message("DAD experienced timeout but continuing after extended waiting period")
        return true
    else
        log_message("Unknown DAD failure type: " .. tostring(failure_type))
        return false
    end
end


-- Function to check DAD status and handle recovery if necessary
local function check_and_handle_dad_failure(interface_name, timeout_seconds, exit_on_failure)
    local linksyswrt = tostring(uci:get("ca_setup", "getmap", "linksyswrt") or "")
    if linksyswrt == "1" then
        return true
    end
    log_message("Performing DAD check on " .. interface_name)
    
    -- Default values
    timeout_seconds = timeout_seconds or 10
    if exit_on_failure == nil then exit_on_failure = true end
    
    -- Check DAD status (timeout_seconds per attempt, 2 retries for reliability)
    local dad_success, dad_status = check_dad_status(interface_name, timeout_seconds, 2)
    
    -- If DAD passed, return success
    if dad_success then
        log_message("DAD check passed on " .. interface_name)
        return true
    end
    
    -- DAD failed, log and attempt recovery
    log_message("DAD check failed with status: " .. dad_status)
    
    -- Attempt recovery
    local recovery_success = recover_from_dad_failure(interface_name, dad_status)
    
    if recovery_success then
        log_message("DAD recovery was successful on " .. interface_name)
        return true
    end
    
    -- Recovery failed, use fallback configuration
    log_message("DAD recovery failed on " .. interface_name .. ", reverting to fallback configuration")
    
    -- Set to DHCP AUTO mode
    VNE = "DHCP AUTO"
    clean_wan_configuration()
    apply_dhcp_configuration()
    
    -- Save state and exit if required
    if exit_on_failure then
        script_lock_disable()
        save_logs_to_persistent_storage()
        os.exit(1)
    end
    
    return false
end


local function check_internet_connectivity(debug_mode)
    debug_mode = debug_mode or false
    local linksyswrt = tostring(uci:get("ca_setup", "getmap", "linksyswrt") or "")
    if linksyswrt == "1" then
        return true
    end
    local function ping_ok(target)
        local rc = sys.call(string.format("ping -q -c1 -W3 %s >/dev/null 2>&1", target))
        return rc == 0
    end

    log_message((debug_mode and "DEBUG MODE: " or "") .. "Checking internet connectivity...")
    
    -- Wait a bit longer for ds-lite/MAP-E tunnel to stabilize
    os.execute("sleep 10")

    local ipv4_targets = { "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9" }
    local max_attempts = 5
    local sleep_time = 5

    for attempt = 1, max_attempts do
        log_message(string.format("%sConnectivity attempt %d/%d", debug_mode and "DEBUG MODE: " or "", attempt, max_attempts))
        
        -- Check IPv4 connectivity (through ds-lite/MAP-E tunnel)
        for _, t in ipairs(ipv4_targets) do
            if debug_mode then
                log_message("DEBUG MODE: ping " .. t)
                local out = sys.exec(string.format("ping -c1 -W3 %s 2>&1", t))
                log_message(out)
            end
            if ping_ok(t) then
                log_message((debug_mode and "DEBUG MODE: " or "") .. "Internet connectivity confirmed via " .. t)
                return true
            end
        end
        
        if attempt < max_attempts then
            log_message(string.format("%sAll targets failed; retry in %ds", debug_mode and "DEBUG MODE: " or "", sleep_time))
            os.execute("sleep " .. sleep_time)
            sleep_time = math.min(sleep_time * 2, 30)
        end
    end

    log_message((debug_mode and "DEBUG MODE: " or "") .. "Internet connectivity check failed after retries")
    return false
end


-- Function to detect duplicate CE MAP-E devices on the same ONU
local function detect_duplicate_ce(wan6_interface, our_prefix)
    if not wan6_interface or not wan6_interface:match("^[%w%.%-%_]+$") then
        log_message("ERROR: Cannot detect duplicate CE - invalid WAN6 interface")
        return false
    end

    local duplicate_detected = false
    log_message("Checking for duplicate MAP-E BR sessions...")

    local map_rules_file = "/tmp/map-wanmap.rules"
    local f = io.open(map_rules_file, "r")
    if not f then
        log_message("B4 address check: SKIPPED - MAP rules file not found")
    else
        local b4_addr
        for line in f:lines() do
            b4_addr = line:match("^RULE_1_IPV6ADDR=(.+)")
            if b4_addr and b4_addr ~= "" then break end
        end
        f:close()

        if b4_addr and b4_addr ~= "" then
            log_message("Found B4 address: " .. b4_addr)

            local handle = io.popen("ip -6 neigh show dev " .. wan6_interface .. " -j 2>/dev/null")
            local neigh_json = handle and handle:read("*a") or ""
            if handle then handle:close() end

            local neigh = json.parse(neigh_json) or {}
            local status = ""
            for _, entry in ipairs(neigh) do
                if entry.dest == b4_addr then
                    status = entry.state or ""
                    break
                end
            end

            log_message("B4 address neighbor status: " .. (status ~= "" and status or "not found"))

            if status == "FAILED" or status == "INCOMPLETE" then
                log_message("B4 address check: FAILED - Problematic status detected")
                duplicate_detected = true
            else
                log_message("B4 address check: PASSED - No problematic B4 address status detected")
            end
        else
            log_message("B4 address check: SKIPPED - Could not find B4 address in rules file")
        end
    end

    log_message("-------- DUPLICATE MAP-E BR DETECTION SUMMARY --------")
    if duplicate_detected then
        log_message("RESULT: DUPLICATE MAP-E BR DETECTED - B4 address has problematic status")
        return true
    else
        log_message("RESULT: NO DUPLICATE MAP-E BR DETECTED - B4 address check passed or inconclusive")
        return false
    end
end


-- v6mig: Provisioning info retrieval function
function v6mig(user, pass)
    -- Get vendor ID from MAC address OUI
    local oui = sys.exec("ip link | grep -o -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | grep -v '00:00:00:00:00:00' | head -n1 | awk -F: '{print tolower($1$2$3)}'")
    if oui then oui = oui:match("^%s*(%x%x%x%x%x%x)%s*$") or "" end
    local vendorid = (#oui == 6) and oui or "acde48"
    log_message("Detected OUI: " .. (oui or "none") .. " -> Vendor ID: " .. vendorid)

    local function readfile(path)
        local f = io.open(path, "r")
        if f then local data = f:read("*a"):gsub("\n", "") f:close() return data end
    end
    
    local function writefile(path, data)
        local f = io.open(path, "w")
        if f then f:write(data) f:close() end
    end

    -- Get URL and build request
    local dns = sys.exec("nslookup -type=txt 4over6.info 2>/dev/null")
    local url = dns:match('text%s*=%s*"[^"]*url=([^%s"]+)')
    local use_cert_validation = url and url:match("t=b$") and true or false
    if not url then return nil, {error = "No URL found"} end

    local token = readfile("/etc/prov_token")
    if tonumber(readfile("/etc/prov_ttl") or "0") < os.time() then token = nil end

    local sep = url:find("?") and "&" or "?"
    local req_url = url .. sep .. "vendorid=" .. vendorid .. "&product=LinksysWRT&version=1_00&capability=ipip,dslite"
    
    -- Include user and pass in the initial request if provided
    if user and pass then
        req_url = req_url .. "&user=" .. urlencode(user) .. "&pass=" .. urlencode(pass)
    end
    
    if token then req_url = req_url .. "&token=" .. token end

       -- Execute request
    local curl_cmd
    if use_cert_validation then
        -- t=b use cert validation
        curl_cmd = "curl --cacert /etc/ssl/certs/ca-certificates.crt -s -w '\\nHTTP_STATUS:%{http_code}\\n' " .. shellquote(req_url)
    else
        -- t=a ignore cert validation
        curl_cmd = "curl -k -s -w '\\nHTTP_STATUS:%{http_code}\\n' " .. shellquote(req_url)
    end
    local handle = io.popen(curl_cmd)
    local result = handle:read("*a")
    handle:close()
    local body, code = result:match("^([%s%S]*)\nHTTP_STATUS:(%d+)\n?$")
    
    if tonumber(code) ~= 200 then return code, {error = "HTTP " .. (code or 0)} end
    
    local data = json.parse(body)
    if not data then return code, {error = "JSON parse failed"} end

    -- Auth retry no longer needed here since we include credentials in first request

    -- Save and return
    if data.token then writefile("/etc/prov_token", data.token) end
    if data.ttl then writefile("/etc/prov_ttl", tostring(os.time() + data.ttl)) end
    
    return code, data
end



-- v6mig_call: Wrapper function with retry logic and error handling
function v6mig_call(user, pass)
    local retry_intervals = {60, 120, 240, 480, 960}  -- 1, 2, 4, 8, 16 minutes
    local max_retry = #retry_intervals + 1

    for attempt = 1, max_retry do
        local code, data = v6mig(user, pass)
        print(string.format("[v6mig] Attempt %d: HTTP %s", attempt, code or "nil"))
        
        if data and not data.error then
            print("Success!")
            return code, data
        elseif data then
            print("Error: " .. data.error)
            if data.message then print("Message: " .. data.message) end
        else
            print("No data returned")
        end
        
        if code == 400 or code == 403 or code == 404 then
            print("Fatal client error. No retry.")
            break
        elseif attempt < max_retry then
            print(string.format("Retrying in %d seconds...", retry_intervals[attempt]))
            os.execute("sleep " .. tostring(retry_intervals[attempt]))
        else
            print("Max retry reached.")
        end
    end
    
    return nil, {error = "All retry attempts failed"}
end

-- Function to set up IPIP prefix hotplug script
local function setup_ipip_prefix_hotplug(mode)
    mode = mode or "s5"
    local script_path = "/usr/lib/lua/mapv6.lua"
    local hotplug_path = "/etc/hotplug.d/iface/99-ipip-prefix-change"
    local lua_bin = "/usr/bin/lua"

    local hotplug_script = string.format([[
cat <<'EOF' > %s
#!/bin/sh
[ "$ACTION" = "ifupdate" ] || exit 0
[ "$INTERFACE" = "wan6" ] || exit 0

to_prefix64() {
    local addr="$1"
    [ -n "$addr" ] || return 1
    addr="${addr%%/*}"
    local p64
    p64="$(/usr/bin/lua /usr/lib/lua/mapv6.lua -prefix64 "$addr" 2>/dev/null | head -n1)"
    [ -n "$p64" ] || return 1
    printf '%%s' "$p64"
    return 0
}

collect_wan6_state() {
    local status
    status="$(ubus call network.interface.wan6 status 2>/dev/null)"

    WAN_DEV="$(echo "$status" | jsonfilter -e '@.l3_device' 2>/dev/null)"
    [ -z "$WAN_DEV" ] && WAN_DEV="$(echo "$status" | jsonfilter -e '@.device' 2>/dev/null)"
    [ -z "$WAN_DEV" ] && WAN_DEV="wan6"

    CUR_PREFIX="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][0].address' 2>/dev/null)"
    [ -z "$CUR_PREFIX" ] && CUR_PREFIX="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][1].address' 2>/dev/null)"
    CUR_PREFIXLEN="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][0].mask' 2>/dev/null)"
    [ -z "$CUR_PREFIXLEN" ] && CUR_PREFIXLEN="$(echo "$status" | jsonfilter -e '@["ipv6-prefix"][1].mask' 2>/dev/null)"
    CUR_PREFIX64="$(to_prefix64 "$CUR_PREFIX")"

    CUR_GUA="$(echo "$status" | jsonfilter -e '@["ipv6-address"][0].address' 2>/dev/null)"
    [ -z "$CUR_GUA" ] && CUR_GUA="$(echo "$status" | jsonfilter -e '@["ipv6-address"][1].address' 2>/dev/null)"
    if [ -z "$CUR_GUA" ]; then
        CUR_GUA="$(ip -6 addr show dev "$WAN_DEV" scope global 2>/dev/null | awk '/inet6 /{print $2}' | sed -n 's#/.*##p' | grep -E '^[23]' | head -n1)"
    fi
    CUR_GUA64="$(to_prefix64 "$CUR_GUA")"

    if [ -z "$CUR_PREFIX64" ]; then
        CUR_PREFIX64="$(ip -6 route show dev "$WAN_DEV" 2>/dev/null | sed -n 's#^\\([0-9A-Fa-f:]*\\)/64.*#\\1#p' | grep -E '^[23]' | head -n1)"
    fi
    if [ -z "$CUR_PREFIX64" ] && [ -n "$CUR_GUA64" ]; then
        CUR_PREFIX64="$CUR_GUA64"
    fi
    if [ -z "$CUR_PREFIXLEN" ] && [ -n "$CUR_GUA64" ]; then
        CUR_PREFIXLEN="64"
    fi

    [ -n "$CUR_PREFIX64" ] || CUR_PREFIX64="-"
    [ -n "$CUR_PREFIXLEN" ] || CUR_PREFIXLEN="-"
    [ -n "$CUR_GUA64" ] || CUR_GUA64="-"
    CUR_SIG="p64=$CUR_PREFIX64;plen=$CUR_PREFIXLEN;g64=$CUR_GUA64"
}

attempt=0
while [ "$attempt" -lt 3 ]; do
    collect_wan6_state
    [ "$CUR_SIG" != "p64=-;plen=-;g64=-" ] && break
    attempt=$((attempt + 1))
    sleep 2
done

SAVED_SIG="$(uci -q get ca_setup.map.cur_sig)"
[ -n "$SAVED_SIG" ] || exit 0
[ "$CUR_SIG" = "$SAVED_SIG" ] && exit 0

%s %s -%s --from-hotplug
EOF
chmod +x %s
]], hotplug_path, lua_bin, script_path, mode, hotplug_path)
    os.execute(hotplug_script)
end


-- Wait for WAN6 to be up with a GUA and default route
-- Also checks for dslite/wanmap/ipip6 interface if applicable
wait_for_wan_ready = function(timeout)
    timeout = timeout or 60
    local deadline = os.time() + timeout
    local want_dslite = uci:get("network", "dslite") ~= nil
    local want_wanmap = uci:get("network", "wanmap") ~= nil
    local want_ipip6 = uci:get("network", "ipip6") ~= nil
    while os.time() < deadline do
        -- Check WAN6 status
        local s = sys.exec("ubus call network.interface.wan6 status 2>/dev/null")
        local up = s:find('"up":%s*true')
        
        -- Check for GUA on wan6 OR on the physical WAN interface
        local gua = s:find('"ipv6%-address"%s*:%s*%[.-"scope"%s*:%s*"global"')
        if not gua then
            -- Also check ip -6 addr for GUA directly
            local ip6_out = sys.exec("ip -6 addr show scope global 2>/dev/null")
            gua = ip6_out:find("inet6%s+[2-3]")
        end
        
        local defrt = sys.exec("ip -6 route show default 2>/dev/null")
        
        -- Check if dslite interface is up (for transix)
        local dslite_up = false
        if want_dslite then
            local dslite_status = sys.exec("ubus call network.interface.dslite status 2>/dev/null")
            if dslite_status:find('"up":%s*true') then
                dslite_up = true
            end
        end
        
        -- Check if wanmap interface is up (for MAP-E)
        local wanmap_up = false
        if want_wanmap then
            local wanmap_status = sys.exec("ubus call network.interface.wanmap status 2>/dev/null")
            if wanmap_status:find('"up":%s*true') then
                wanmap_up = true
            end
        end

        -- Check if ipip6 interface is up (for IPIP)
        local ipip_up = false
        if want_ipip6 then
            local ipip_status = sys.exec("ubus call network.interface.ipip6 status 2>/dev/null")
            if ipip_status:find('"up":%s*true') then
                ipip_up = true
            end
        end

        local tunnels_ok = true
        if want_dslite and not dslite_up then tunnels_ok = false end
        if want_wanmap and not wanmap_up then tunnels_ok = false end
        if want_ipip6 and not ipip_up then tunnels_ok = false end

        if up and gua and defrt ~= "" and tunnels_ok then
            if want_dslite then
                log_message("DS-Lite tunnel ready")
            elseif want_wanmap then
                log_message("MAP-E interface ready")
            elseif want_ipip6 then
                log_message("IPIP interface ready")
            else
                log_message("WAN6 ready (up, GUA, default route present)")
            end
            return true
        end
        os.execute("sleep 2")
    end
    if want_dslite then
        log_message("DS-Lite tunnel not ready after " .. timeout .. "s, proceeding anyway")
    elseif want_wanmap then
        log_message("MAP-E interface not ready after " .. timeout .. "s, proceeding anyway")
    elseif want_ipip6 then
        log_message("IPIP interface not ready after " .. timeout .. "s, proceeding anyway")
    else
        log_message("WAN6 not ready after " .. timeout .. "s, proceeding anyway")
    end
    return false
end


-------------------------------------
-------------------------------------
-- Main operation routine starts here
-------------------------------------
-------------------------------------

local function main()

    -- Check for duplicate execution
    if not dupe_exec_check() then os.exit(0) end

    -- Variable to track if we were called from boot
    local from_boot = false

    -- Parse command line arguments
    for i, arg_val in ipairs(arg) do
        if arg_val == "--random-delay" then
            -- Add a random delay (0-10 minutes) to spread server load for cron executions
            math.randomseed(os.time())
            local delay_seconds = math.random(0, 600)
            log_message("Called from cron, waiting " .. delay_seconds .. " seconds to spread load")
            os.execute("sleep " .. delay_seconds)
        elseif arg_val == "--from-boot" then
            -- Flag that we're running from boot
            from_boot = true
            log_message("Execution triggered by system boot")
        end
    end

    -- Check for lock file
    script_lock_enable()
    ensure_dscp_zero_nft()

    -- Linksys Japanese IPoE Configuration Program
    log_message("----------------------------------------------")
    log_message(" Japan NTT IPoE IPv4 over IPv6 Config Program ")
    log_message("----------------------------------------------")
    local current_time = os.date("%Y-%m-%d %H:%M:%S")
    log_message("timestamp: " .. current_time)
    log_message("IPoE Auto Configuration Program Started")

    -- Determine the WAN interface name
    wan_interface = get_ifname("wan")
    wan6_interface = get_ifname("wan6")
    log_message("WAN interface: " .. wan_interface)
    log_message("WAN6 interface: " .. wan6_interface)

    -- Check for IP conflicts with parent device
    check_ip_duplication()

    -- Retrieve IPv6 WAN address, check timer operation, etc.
    wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()   
    local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
    local cur_prefix64 = cur_wan_state.prefix64

    -- Check for DAD issues before proceeding
    if not check_and_handle_dad_failure("wan6") then
        -- This code will only run if exit_on_failure is set to false
        log_message("Continuing despite DAD failure")
    end

    wan32_ipv6, wan40_ipv6 = wan32_40(wan_ipv6)
    samewancheck = samewancheckfunc(cur_wan_state)
    update_wan6_cur_prefix(cur_wan_state)
    reloadtimer = reloadtimer()

    -- Determine VNE (Virtual Network Environment)
    VNE = determineVNE(wan_ipv6)
    log_message("VNE type: "..VNE)
 
    -- Check if there is a router in front
    check_under_router(wan_interface, wan6_interface)  -- Check if the first hop is a private IP
    
    -- Check the presence of NTT HGW and the status of IPOE software
    check_ntt_hgw()

    log_message(string.format("Mode summary: qsdk=%s VNE=%s ipv6_fixlen=%s under_router=%s wan6_if=%s",
        tostring(qsdk), tostring(VNE), tostring(ipv6_fixlen), tostring(under_router), tostring(wan6_interface)))
    
        -- Force re-setup if under_router and VNE are inconsistent
    local map_vne = uci:get("ca_setup", "map", "VNE") or ""
    if under_router == 3 and map_vne == "DHCP AUTO" then
        log_message("Inconsistent state: under_router=3 but VNE is DHCP AUTO. Forcing re-setup.")
        samewancheck = "N"
    elseif under_router == 2 and (map_vne ~= "DHCP AUTO" and (map_vne or "") ~= "") then
        log_message("Inconsistent state: under_router=2 but VNE is not DHCP AUTO. Forcing re-setup.")
        samewancheck = "N"
    end

    -- Startup routine tasks
    currentTime = os.time()
    timestamp = os.date("%Y-%m-%d %H:%M:%S", currentTime)
    urkey, brandcheck, sysinfo_model = brand_status()    
    mapcount, init_execute = mapcount_check()
   
    -- Recovery routine when WAN STATUS is unknown
    if VNE == "unknown" and ipv6Prefix == "not found" then recovery_wan() end
   
    -- Automatically execute data retrieval on page load
    if reloadtimer == "Y" and brandcheck == "OK" and VNE == "v6_plus" and (under_router == 0 or under_router == 3) then
        log_message("setting v6 plus map configuration")
        rule_param(nil, from_boot)
            if samewancheck == "N" then
                log_message("Updating network settings for new WAN connection...")
                local peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6 = get_mapconfig(wan_ipv6, ipv6_56, ipv6_fixlen, from_boot)

                clean_wan_configuration()
                configure_mape_connection(peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, under_router)

                -- Add the non-matching FMR rules to the UCI configuration
                        local enfmrStr = uci:get("ca_setup", "map", "fmr")
                        local fmr_json = decryptedData(enfmrStr)
                        local fmr = json.parse(fmr_json)
                        local fmr_uci_entries = {}
                        for i, rule in ipairs(fmr) do
                            local rule_prefix = rule.ipv6 and rule.ipv6:match("^([^/]+)")
                            
                            if not (rule_prefix and ipv6_prefix and rule_prefix == ipv6_prefix) then
                                if rule.ipv6 and rule.ipv4 and rule.ea_length and rule.psid_offset then
                                    local fmr_entry = string.format("%s,%s,%s,%s", 
                                        rule.ipv6, rule.ipv4, rule.ea_length, rule.psid_offset)
                                    table.insert(fmr_uci_entries, fmr_entry)
                                end
                            end
                        end                   
                        if #fmr_uci_entries > 0 then
                            uci:set("network", "wanmap", "fmr", "1")
                            uci:set("network", "wanmap", "draft03", "1")
                            uci:set_list("network", "wanmap", "rule", fmr_uci_entries)
                            uci:commit("network")
                            log_message("Added " .. #fmr_uci_entries .. " additional FMR rules for v6 plus.")
                        end

                tune_sysctl(ipv6_fixlen, under_router)
                network_restart_handler("MAP-E configuration", 60)

                -- Check DAD status on MAP-E interface
                log_message("Checking DAD status after MAP-E configuration...")
                if check_and_handle_dad_failure("wanmap", 15) then
                    -- DAD check passed, proceed with normal flow
                    log_message("DAD check passed, v6_plus configured successfully")

                    -- Only run duplicate CE detection if connectivity check fails
                    if not check_internet_connectivity() then
                        log_message("Internet connectivity check failed, checking for duplicate CE...")
                        
                        if detect_duplicate_ce(wan6_interface, ipv6_56) then
                            log_message("Detected duplicate CE - cannot proceed with MAP-E configuration")
                            -- Fall back to DHCP auto configuration
                            apply_dhcp_configuration()
                            schedule_next_run(from_boot)
                            script_lock_disable()
                            save_logs_to_persistent_storage()
                            return
                        end
                        
                        log_message("No duplicate CE detected despite connectivity failure. Continuing with current configuration.")
                    else
                        log_message("Internet connectivity confirmed, skipping duplicate CE check.")
                    end 

                    reboot_after_new_setup("MAP-E", from_boot)
                end
            else     
                log_message("No change detected in the WAN address; existing settings remain valid.")
                schedule_next_run(from_boot)
                script_lock_disable()
                save_logs_to_persistent_storage()
            end
    elseif reloadtimer == "Y" and brandcheck == "OK" and VNE == "OCN_virtualconnect" and (under_router == 0 or under_router == 3) then
        log_message("setting OCN virtual connect map configuration")
        rule_param(nil, from_boot)
            if samewancheck == "N" then
                log_message("Updating network settings for new WAN connection...")
                local peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6 = get_mapconfig_ocn(wan_ipv6, ipv6_56, ipv6_fixlen, from_boot)

                clean_wan_configuration()    
                configure_mape_connection(peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, under_router)
                tune_sysctl(ipv6_fixlen, under_router)
                network_restart_handler("MAP-E configuration", 60)

                -- Check DAD status on MAP-E interface
                log_message("Checking DAD status after MAP-E configuration...")
                if check_and_handle_dad_failure("wanmap", 15) then
                    -- DAD check passed, proceed with normal flow
                    log_message("DAD check passed, OCN_virtualconnect configured successfully")
                    check_internet_connectivity()
                    reboot_after_new_setup("MAP-E", from_boot)
                end
            else
                log_message("No change detected in the WAN address; existing settings remain valid.")
                schedule_next_run(from_boot)
                script_lock_disable()
                save_logs_to_persistent_storage()
            end
    elseif reloadtimer == "Y" and brandcheck == "OK" and VNE == "ipv6_option" and (under_router == 0 or under_router == 3) then
        log_message("setting BIGLOBE IPv6 option map configuration")
        rule_param(nil, from_boot)
            if samewancheck == "N" then
                log_message("Updating network settings for new WAN connection...")
                local peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6 = get_mapconfig(wan_ipv6, ipv6_56, ipv6_fixlen, from_boot)
            
                clean_wan_configuration()
                configure_mape_connection(peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, under_router)
                tune_sysctl(ipv6_fixlen, under_router)
                network_restart_handler("MAP-E configuration", 60)

                -- Check DAD status on MAP-E interface
                log_message("Checking DAD status after MAP-E configuration...")
                if check_and_handle_dad_failure("wanmap", 15) then
                    -- DAD check passed, proceed with normal flow
                    log_message("DAD check passed, BIGLOB IPv6_option configured successfully")
                    check_internet_connectivity()
                    reboot_after_new_setup("MAP-E", from_boot)
                end
            else
                log_message("No change detected in the WAN address; existing settings remain valid.")
                schedule_next_run(from_boot)
                script_lock_disable()
                save_logs_to_persistent_storage()
            end 
    elseif reloadtimer == "Y" and brandcheck == "OK" and VNE == "transix" and (under_router == 0 or under_router == 3) and samewancheck == "N" then
                log_message("setting transix ds-lite configuration")
                gw_aftr = uci:get("ca_setup", "ipoe_transix", "gw_aftr")
                clean_wan_configuration()    
                configure_dslite_connection(gw_aftr, ipv6_fixlen, ipv6_56, under_router)
                save_ca_setup_config_other()
                tune_sysctl(ipv6_fixlen, under_router)

                -- Restart network to apply MAP-E configuration
                network_restart_handler("ds-lite configuration", 60)

                -- Check DAD status on WAN6 interface
                log_message("Checking DAD status after ds-lite configuration...")
                if check_and_handle_dad_failure("wan6", 15) then
                    -- DAD check passed, proceed with normal flow
                    log_message("DAD check passed, transix configured successfully")
                    check_internet_connectivity()
                    reboot_after_new_setup("DS-Lite", from_boot)
                end
    
    elseif reloadtimer == "Y" and brandcheck == "OK" and VNE == "v6_connect" and (under_router == 0 or under_router == 3) and samewancheck == "N" then
                log_message("setting v6 connect ds-lite configuration")   

                -- Get gw_aftr from v6mig service
                log_message("Retrieving v6_connect gateway information from v6mig service...")
                local code, data = v6mig_call()

                if not data or data.error then
                    log_message("Failed to retrieve v6_connect gateway information: " .. (data and data.error or "unknown error"))
                    log_message("Aborting v6_connect configuration")
                    schedule_next_run(from_boot)
                    script_lock_disable()
                    save_logs_to_persistent_storage()
                    return
                end

                -- Extract gateway from v6mig response
                gw_aftr = data.aftr or (data.dslite and data.dslite.aftr) or data.gateway or data.gw_aftr
                if not gw_aftr or gw_aftr == "" then
                    log_message("v6mig response does not contain gateway information")
                    log_message("No gateway information available, aborting v6_connect configuration")
                    schedule_next_run(from_boot)
                    script_lock_disable()
                    save_logs_to_persistent_storage()
                    return
                end

                log_message("Retrieved v6_connect gateway from v6mig: " .. gw_aftr)

                clean_wan_configuration()    
                configure_dslite_connection(gw_aftr, ipv6_fixlen, ipv6_56, under_router)
                save_ca_setup_config_other()
                tune_sysctl(ipv6_fixlen, under_router)
                network_restart_handler("ds-lite configuration", 60)

                -- Check DAD status on WAN6 interface
                log_message("Checking DAD status after ds-lite configuration...")
                if check_and_handle_dad_failure("wan6", 15) then
                    -- DAD check passed, proceed with normal flow
                    log_message("DAD check passed, v6_connect configured successfully")
                    check_internet_connectivity()
                    reboot_after_new_setup("DS-Lite", from_boot)
                end
    
    elseif reloadtimer == "Y" and brandcheck == "OK" and VNE == "Xpass" and (under_router == 0 or under_router == 3) and samewancheck == "N" then
                log_message("setting Xpass ds-lite configuration")        
                gw_aftr = uci:get("ca_setup", "ipoe_xpass", "gw_aftr")
                clean_wan_configuration()    
                configure_dslite_connection(gw_aftr, ipv6_fixlen, ipv6_56, under_router) 
                save_ca_setup_config_other()
                tune_sysctl(ipv6_fixlen, under_router)
                network_restart_handler("ds-lite configuration", 60)

                -- Check DAD status on WAN6 interface
                log_message("Checking DAD status after ds-lite configuration...")
                if check_and_handle_dad_failure("wan6", 15) then
                    -- DAD check passed, proceed with normal flow
                    log_message("DAD check passed, Xpass configured successfully")
                    check_internet_connectivity()
                    reboot_after_new_setup("DS-Lite", from_boot)
                end

    elseif reloadtimer == "Y" and brandcheck == "OK" and VNE == "NTT_EAST" and (under_router == 0 or under_router == 3) and samewancheck == "N" then
                log_message("The IPoE connection service seems to be disabled. Is it not yet activated or is it only an IPv4 PPPoE connection?")
                schedule_next_run(from_boot)
                script_lock_disable()
                save_logs_to_persistent_storage()

    elseif reloadtimer == "Y" and brandcheck == "OK" and VNE == "NTT_WEST" and (under_router == 0 or under_router == 3) and samewancheck == "N" then
                log_message("The IPoE connection service seems to be disabled. Is it not yet activated or is it only an IPv4 PPPoE connection?")
                schedule_next_run(from_boot)
                script_lock_disable()
                save_logs_to_persistent_storage()
        
    elseif (under_router == 1 or under_router == 2) and samewancheck == "N" then
                -- Since it should be DHCP automatic, check and delete unrelated WAN settings, and revert to DHCP automatic settings
                log_message("setting DHCP auto configuration")
                apply_dhcp_configuration()
                VNE = "DHCP AUTO"
                save_ca_setup_config_other()
                schedule_next_run(from_boot)
                script_lock_disable()
                save_logs_to_persistent_storage()

    elseif (under_router == 1 or under_router == 2) and samewancheck == "Y" and VNE ~= "DHCP AUTO" then
                -- Since it should be DHCP automatic, check and delete unrelated WAN settings, and revert to DHCP automatic settings
                log_message("setting DHCP auto configuration")
                apply_dhcp_configuration()
                VNE = "DHCP AUTO"
                save_ca_setup_config_other()
                schedule_next_run(from_boot)
                script_lock_disable()
                save_logs_to_persistent_storage()

            
    else
        local WANTYPE = uci:get("ca_setup", "map", "VNE") or "nil"
        local mapcount = uci:get("ca_setup", "map", "mapcount") or "0"
        mapcount = tonumber(mapcount) + 1
        uci:set("ca_setup", "map", "mapcount", mapcount)
        uci:set("ca_setup", "map", "ostime", os.time())
        uci:set("ca_setup", "map", "time", timestamp)
        uci:commit("ca_setup")
        log_message("no change required. Current config: " .. WANTYPE .. " mapcount: " .. mapcount)
        schedule_next_run(from_boot)
        script_lock_disable()
        save_logs_to_persistent_storage()
    end

end

-- Process based on command line arguments
if #arg > 0 then
    local mode = arg[1]
    if mode == "-prefix64" then
        local input = arg[2] or ""
        local prefix64 = extract_ipv6_64(input)
        if prefix64 and prefix64 ~= "" then
            print(prefix64)
            os.exit(0)
        end
        os.exit(1)
    end
    if mode and mode:match("^%-s%d+$") then
        ensure_dscp_zero_nft()
    end

    if mode == "--from-boot" or mode == "--random-delay" then
        -- Pass control to main() for these special arguments
                main()

    elseif mode == "--from-hotplug" then
        -- When called from hotplug event
                log_message("Script executed by hotplug event")
                -- For dynamic IP auto-ipoe, reset to DHCP auto and reboot only when WAN6 prefix changes
                script_lock_enable()
                log_message("WAN6 change detected via hotplug. Resetting to DHCP auto and rebooting.")
                reset_wan_to_dhcp(true)
                setup_auto_ipoe_one_shot()
                save_logs_to_persistent_storage()
                reboot_system()
                os.exit(0)

    elseif mode == "-m1" then
        -- v6_plus map rule feedback routine
                log_message("v6 plus rule feedback routine")
                wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status() 
                VNE = determineVNE(wan_ipv6)              
                urkey, brandcheck, sysinfo_model = brand_status()
                rule_param()
                local peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6 = get_mapconfig(wan_ipv6, ipv6_56, ipv6_fixlen)
                 local matching_fmr_data = {
                    matching_fmr = {
                        peeraddr = peeraddr or "nil",
                        ipv4_prefix = ipv4_prefix or "nil",
                        ipv4_prefixlen = ipv4_prefixlen or "nil",
                        ipv6_prefix = ipv6_prefix or "nil",
                        ipv6_prefixlen = ipv6_prefixlen or "nil",
                        ealen = ealen or "nil",
                        psidlen = psidlen or "nil",
                        offset = offset or "nil",
                        ipv6_fixlen = ipv6_fixlen or "nil",
                        ipv6_56 = ipv6_56 or "nil"
                    }
                }
                
                local json_output = json.stringify(matching_fmr_data, true)
                
                log_message(json_output)
                save_logs_to_persistent_storage()
     
    elseif mode == "-m2" then
        -- OCN_virtualconnect map rule feedback routine
                log_message("OCN virtual connect rule feedback routine")
                wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()        
                VNE = determineVNE(wan_ipv6)
                urkey, brandcheck, sysinfo_model = brand_status()
                rule_param()
                local peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6 = get_mapconfig_ocn(wan_ipv6, ipv6_56, ipv6_fixlen)
                local matching_fmr_data = {
                    matching_fmr = {
                        peeraddr = peeraddr or "nil",
                        ipv4_prefix = ipv4_prefix or "nil",
                        ipv4_prefixlen = ipv4_prefixlen or "nil",
                        ipv6_prefix = ipv6_prefix or "nil",
                        ipv6_prefixlen = ipv6_prefixlen or "nil",
                        ealen = ealen or "nil",
                        psidlen = psidlen or "nil",
                        offset = offset or "nil",
                        ipv6_fixlen = ipv6_fixlen or "nil",
                        ipv6_56 = ipv6_56 or "nil"
                    }
                }
                
                local json_output = json.stringify(matching_fmr_data, true)
                
                log_message(json_output)
                save_logs_to_persistent_storage()
        
    elseif mode == "-m3" then
        -- BIGLOBE ipv6_option map rule feedback routine
                log_message("BIGLOBE IPv6 option rule feedback routine")    
                wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status() 
                VNE = determineVNE(wan_ipv6)              
                urkey, brandcheck, sysinfo_model = brand_status()
                rule_param()
                local peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6 = get_mapconfig(wan_ipv6, ipv6_56, ipv6_fixlen)
                 local matching_fmr_data = {
                    matching_fmr = {
                        peeraddr = peeraddr or "nil",
                        ipv4_prefix = ipv4_prefix or "nil",
                        ipv4_prefixlen = ipv4_prefixlen or "nil",
                        ipv6_prefix = ipv6_prefix or "nil",
                        ipv6_prefixlen = ipv6_prefixlen or "nil",
                        ealen = ealen or "nil",
                        psidlen = psidlen or "nil",
                        offset = offset or "nil",
                        ipv6_fixlen = ipv6_fixlen or "nil",
                        ipv6_56 = ipv6_56 or "nil"
                    }
                }
                
                local json_output = json.stringify(matching_fmr_data, true)
                
                log_message(json_output)
                save_logs_to_persistent_storage()

    elseif mode == "-s0" then
        -- Standard IPIP connection setup module (no prefix update/hotplug)
        log_message("----------------------------------------------")
        log_message("        Standard IPIP connection setup        ")
        log_message("----------------------------------------------")
        local current_time = os.date("%Y-%m-%d %H:%M:%S")
        log_message("timestamp: " .. current_time)
        wan6_interface = get_ifname("wan6")
        wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()
        local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
        local cur_prefix64 = cur_wan_state.prefix64
        update_wan6_cur_prefix(cur_wan_state)
        urkey, brandcheck, sysinfo_model = brand_status()

        -- Get parameters: ipv6_remote, ipv6_ifaceid, ipv4_addr
        local ipv6_remote = arg[2]
        local ipv6_ifaceid = arg[3]
        local ipv4_addr   = arg[4]

        if not (ipv6_remote and ipv6_ifaceid and ipv4_addr) then
            log_message("ERROR: Required parameters are missing")
            save_logs_to_persistent_storage()
            os.exit(1)
        end

        -- Save config for reference (optional)
        uci:section("ca_setup", "settings", "std_ipip", {
            ipv6_remote = ipv6_remote,
            ipv6_ifaceid = ipv6_ifaceid,
            ipv4_addr = ipv4_addr,
            last_wan_sig = cur_wan_state.sig,
            setup_time = os.time()
        })
        uci:commit("ca_setup")
        log_message("Saved standard IPIP tunnel information")

        -- Compose local IPv6 address
        local ipv6_local = concat_ipv6_prefix_and_ifaceid(ipv6_56, ipv6_ifaceid)

        -- Apply configuration
        clean_wan_configuration()
        tune_sysctl(ipv6_fixlen, under_router)
        configure_ipip_connection(ipv4_addr, ipv6_local, ipv6_remote, ipv6_ifaceid, ipv6_fixlen, ipv6_56)
        network_restart_handler("IPIP configuration", 60)
        check_internet_connectivity()
        log_message("Standard IPIP setup completed")
        save_logs_to_persistent_storage()
        os.exit(0)


    elseif mode == "-s1" then
            -- v6 Plus Static IP IPIP connection setup module
            log_message("----------------------------------------------")
            log_message("      v6 Plus Static IP IPIP connection setup  ")
            log_message("----------------------------------------------")
            local current_time = os.date("%Y-%m-%d %H:%M:%S")
            log_message("timestamp: " .. current_time)
            wan6_interface = get_ifname("wan6")
            wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()
            local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
            local cur_prefix64 = cur_wan_state.prefix64
            update_wan6_cur_prefix(cur_wan_state)
            urkey, brandcheck, sysinfo_model = brand_status()

            -- Get parameters
            local from_hotplug = arg[2] == "--from-hotplug"
            local ipv6_remote = from_hotplug and nil or arg[2]
            local ipv6_ifaceid = from_hotplug and nil or arg[3]
            local ipv4_addr   = from_hotplug and nil or arg[4]
            local user_id     = from_hotplug and nil or arg[5]
            local user_pass   = from_hotplug and nil or arg[6]

            -- Use saved values when called from hotplug or if parameters are missing
            if from_hotplug or not (ipv6_remote and ipv6_ifaceid and ipv4_addr and user_id and user_pass) then
                ipv6_remote = uci:get("ca_setup", "v6plus_ipip", "ipv6_remote")
                ipv6_ifaceid = uci:get("ca_setup", "v6plus_ipip", "ipv6_ifaceid")
                ipv4_addr = uci:get("ca_setup", "v6plus_ipip", "ipv4_addr")
                user_id = decryptedData(uci:get("ca_setup", "v6plus_ipip", "user_id"))
                user_pass = decryptedData(uci:get("ca_setup", "v6plus_ipip", "user_pass"))
                if not (ipv6_remote and ipv6_ifaceid and ipv4_addr and user_id and user_pass) then
                    log_message("ERROR: Required parameters are missing")
                    save_logs_to_persistent_storage()
                    os.exit(1)
                end
            else
                -- Save on first run
                uci:section("ca_setup", "settings", "v6plus_ipip", {
                    ipv6_remote = ipv6_remote,
                    ipv6_ifaceid = ipv6_ifaceid,
                    ipv4_addr = ipv4_addr,
                    user_id = encrypt_data(user_id, urkey),
                    user_pass = encrypt_data(user_pass, urkey),
                    last_wan_sig = cur_wan_state.sig,
                    setup_time = os.time()
                })
                uci:commit("ca_setup")
                log_message("Saved v6 Plus IPIP authentication information")
            end

            -- Only re-execute on prefix change
            if should_skip_hotplug_reconfig("v6plus_ipip", cur_wan_state, from_hotplug) then
                save_logs_to_persistent_storage()
                os.exit(0)
            end

            -- Notify v6 Plus update server (main difference from transix)
            local update_url = string.format(
                "http://fcs.enabler.ne.jp/update?user=%s&pass=%s",
                urlencode(user_id), urlencode(user_pass)
            )
            local handle = io.popen("curl -s -w '\\nHTTP_STATUS:%{http_code}\\n' " .. shellquote(update_url))
            local result = handle:read("*a")
            handle:close()
            local body, code = result:match("^([%s%S]*)\nHTTP_STATUS:(%d+)\n?$")
            log_message("v6 Plus update server response: " .. (body or "") .. " (HTTP " .. (code or "") .. ")")

            if tonumber(code) ~= 200 or not body:find("OK") then
                log_message("ERROR: Failed to notify v6 Plus update server")
                save_logs_to_persistent_storage()
                os.exit(1)
            end

            -- Apply configuration
            save_last_wan_state("v6plus_ipip", cur_wan_state)
            uci:set("ca_setup", "v6plus_ipip", "setup_time", os.time())
            uci:commit("ca_setup")

            -- IPIP interface configuration
            local ipv6_local = concat_ipv6_prefix_and_ifaceid(ipv6_56, ipv6_ifaceid)
            clean_wan_configuration()
            tune_sysctl(ipv6_fixlen, under_router)
            configure_ipip_connection(ipv4_addr, ipv6_local, ipv6_remote, ipv6_ifaceid, ipv6_fixlen, ipv6_56)
            network_restart_handler("IPIP configuration", 60)
            check_internet_connectivity()

            -- Set up hotplug script (only on first run)
            if not from_hotplug then
                log_message("Setting up v6 Plus IPIP hotplug handler with prefix detection...")
                setup_ipip_prefix_hotplug("s1")
                log_message("v6 Plus IPIP setup completed")
                save_logs_to_persistent_storage()
            else
            log_message("v6 Plus IPIP setup completed (from hotplug), rebooting router...")
            save_logs_to_persistent_storage()
            os.execute("sleep 5")
            reboot_system()
        end

    elseif mode == "-s2" then

        -- Check for duplicate execution
        if not dupe_exec_check() then os.exit(0) end

        -- Variable to track if we were called from boot and hotplug
        local from_boot = false
        local from_hotplug = false

        -- Parse command line arguments
        for i, arg_val in ipairs(arg) do
            if arg_val == "--random-delay" then
                math.randomseed(os.time())
                local delay_seconds = math.random(0, 600)
                log_message("Called from cron, waiting " .. delay_seconds .. " seconds to spread load")
                os.execute("sleep " .. delay_seconds)
            elseif arg_val == "--from-boot" then
                from_boot = true
                log_message("Execution triggered by system boot")
            elseif arg_val == "--from-hotplug" then
                from_hotplug = true
                log_message("Execution triggered by hotplug event")
            end
        end

        -- Check for lock file
        script_lock_enable()

        -- OCN Virtual Connect Static MAP-E Setup Module
        log_message("----------------------------------------------")
        log_message("   OCN Virtual Connect Static MAP-E Setup     ")
        log_message("----------------------------------------------")
        local current_epoch = os.time()
        local current_time = os.date("%Y-%m-%d %H:%M:%S", current_epoch)
        log_message("timestamp: " .. current_time)
        timestamp = current_time
        
        wan_interface = get_ifname("wan")
        wan6_interface = get_ifname("wan6")
        wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()
        local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
        local cur_prefix64 = cur_wan_state.prefix64

        wan32_ipv6, wan40_ipv6 = wan32_40(wan_ipv6)
        samewancheck = samewancheckfunc(cur_wan_state)
        update_wan6_cur_prefix(cur_wan_state)
        reloadtimer = reloadtimer()
        
        VNE = determineVNE(wan_ipv6)
        -- skip duplicate router check for OCN static
        -- check_under_router(wan_interface, wan6_interface) 
        -- check_ntt_hgw()

        urkey, brandcheck, sysinfo_model = brand_status()    
        mapcount, init_execute = mapcount_check()

        local function stay_dchp_ocn_static()
            -- It is not OCN Virtunal Connect MAP-E compatible or under_router requires DHCP auto
            log_message("Network is not ready with OCN MAP-E static. Setting DHCP auto configuration")
            apply_dhcp_configuration()
            VNE = "DHCP AUTO"
            save_ca_setup_config_other()
            schedule_next_run(false, "ocn_static")
            script_lock_disable()
            save_logs_to_persistent_storage()
            os.exit(0)
        end

        -- Recovery routine when WAN STATUS is unknown
        if VNE == "unknown" and ipv6Prefix == "not found" then recovery_wan() end     

        -- Only re-execute on prefix change
        if should_skip_hotplug_reconfig("ocn_static_map", cur_wan_state, from_hotplug) then
            script_lock_disable()
            save_logs_to_persistent_storage()
            os.exit(0)
        end

        local function load_static_rule_state()
            local host = uci:get("ca_setup", "map", "hostname")
            local enfmrStr = uci:get("ca_setup", "map", "fmr")
            if not host or host == "" or not enfmrStr or enfmrStr == "" then
                return nil
            end
            local fmr_json = decryptedData(enfmrStr)
            local fmr = json.parse(fmr_json or "{}") or {}
            local rule = fmr[1]
            if not rule then
                return nil
            end
            return {
                hostname = host,
                fmr = fmr,
                rule = rule
            }
        end

        local function notify_ocn_update(hostname)
            local encoded_hostname = urlencode(hostname)
            local enParam3 = uci:get("ca_setup", "getmap", "param3")
            local ocn_auth = enParam3 and decryptedData(enParam3) or ""
            local update_url = "https://ipoe-static.ocn.ad.jp/nic/update?hostname=" .. encoded_hostname
            local intervals = {120, 240, 480, 960, 1920, 3600}
            local curl_insecure_flag = should_skip_cert_verification() and "-k " or ""
            local function do_request()
                local curl_cmd = string.format(
                    "curl %s-s --tlsv1.2 --ipv6 -u %s -w '\\nHTTP_STATUS:%%{http_code}\\n' %s",
                    curl_insecure_flag, shellquote(ocn_auth), shellquote(update_url)
                )
                local handle = io.popen(curl_cmd)
                local result = handle:read("*a")
                handle:close()
                local body, code = result:match("^([%s%S]*)\nHTTP_STATUS:(%d+)\n?$")
                local status_word = body and body:match("^%s*(%w+)")
                local http_ok = tonumber(code) == 200
                local success = status_word == "good" or status_word == "nochg"
                return http_ok, success, status_word, body, code
            end
            local attempt = 1
            while true do
                local http_ok, success, status_word, body, code = do_request()
                log_message("OCN update server response: " .. (body or "") .. " (HTTP " .. (code or "") .. ")")
                if http_ok and status_word == "nohost" then
                    log_message("ERROR: OCN update returned 'nohost'; not retrying")
                    return false
                end
                if http_ok and success then
                    return true
                end
                if attempt > #intervals then
                    log_message("ERROR: Failed to notify OCN update server after retries (status: " .. (status_word or "unknown") .. ")")
                    return false
                end
                local wait_sec = intervals[attempt]
                log_message(string.format("OCN update failed (status: %s, HTTP %s); retrying in %d seconds",
                    status_word or "unknown", code or "n/a", wait_sec))
                os.execute("sleep " .. wait_sec)
                attempt = attempt + 1
            end
        end

        -- only continue when OCN static makes sense
        if not (VNE == "OCN_virtualconnect" and (under_router == 0 or under_router == 3)) then
            log_message("Not an OCN Virtual Connect static scenario (VNE=" .. tostring(VNE) .. ", under_router=" .. tostring(under_router) .. "), falling back to DHCP auto.")
            stay_dchp_ocn_static()
        end

        local function fetch_static_rules()
            local ok, err = pcall(rule_param, "static", from_boot)
            if not ok then
                log_message("Failed to fetch static MAP rule: " .. tostring(err) .. " -> reverting to DHCP.")
                stay_dchp_ocn_static()
            end
            return load_static_rule_state()
        end

        local state = load_static_rule_state()
        local need_prefetch = (state == nil)

        if need_prefetch then
            log_message("No saved static MAP rule; fetching before configuration.")
            state = fetch_static_rules()
            if not state then
                log_message("ERROR: Static MAP rule fetch failed; reverting to DHCP.")
                stay_dchp_ocn_static()
            end
        else
            log_message("Notifying OCN update server of current hostname")
            if not notify_ocn_update(state.hostname) then
                script_lock_disable()
                save_logs_to_persistent_storage()
                os.exit(1)
            end

            log_message("Refreshing static MAP rule after OCN notification")
            state = fetch_static_rules()
            if not state then
                log_message("ERROR: MAP rule missing after refresh; reverting to DHCP.")
                stay_dchp_ocn_static()
            end
        end

        -- Save last WAN /64 state
        save_last_wan_state("ocn_static_map", cur_wan_state)
        uci:set("ca_setup", "ocn_static_map", "setup_time", os.time())
        uci:commit("ca_setup")

        if reloadtimer == "Y" and brandcheck == "OK" and VNE == "OCN_virtualconnect" and (under_router == 0 or under_router == 3) then
            log_message("setting OCN virtual connect map-e static configuration")

            if samewancheck == "N" then
                log_message("Updating network settings for new WAN connection...")
                local rule = state.rule
                if not rule then
                    log_message("ERROR: Static MAP rule missing after fetch.")
                    stay_dchp_ocn_static()
                end
                local peeraddr = rule and rule.br_ipv6
                local ipv4_prefix_with_len = rule and rule.ipv4
                local ipv6_prefix_with_len = rule and rule.ipv6
                if not (peeraddr and ipv4_prefix_with_len and ipv6_prefix_with_len) then
                    log_message("ERROR: Static MAP rule incomplete; reverting to DHCP.")
                    stay_dchp_ocn_static()
                end
                local ipv4_prefixlen = tonumber(ipv4_prefix_with_len:match("/(%d+)$"))
                local ipv6_prefixlen = tonumber(ipv6_prefix_with_len:match("/(%d+)$"))
                local ipv4_prefix = ipv4_prefix_with_len:match("([^/]+)")
                local ipv6_prefix = ipv6_prefix_with_len:match("([^/]+)")
                local ealen = rule.ea_length
                local offset = rule.psid_offset
                local psidlen = ealen - (32 - ipv4_prefixlen)
                clean_wan_configuration()
                configure_mape_connection(peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, under_router)   
                tune_sysctl(ipv6_fixlen, under_router)
                network_restart_handler("MAP-E configuration", 60)
                if need_prefetch then
                    log_message("Notifying OCN update server after MAP-E activation (initial run)")
                    if not notify_ocn_update(state.hostname) then
                        script_lock_disable()
                        save_logs_to_persistent_storage()
                        os.exit(1)
                    end
                end
                log_message("OCN_virtualconnect static ip configured successfully")
                schedule_next_run(false, "ocn_static")
            else
                log_message("No change detected in the WAN address; existing settings remain valid.")
                schedule_next_run(false, "ocn_static")
            end
        else
            -- Not OCN Virtual Connect MAP-E compatible or under_router requires DHCP auto
            stay_dchp_ocn_static()
        end


        local hotplug_key = "hotplug_s2_installed"
        local hotplug_installed = uci:get("ca_setup", "ocn_static_map", hotplug_key) == "1"

        if not from_hotplug and not hotplug_installed then
            log_message("Setting up OCN MAP-E hotplug handler with prefix detection...")
            setup_ipip_prefix_hotplug("s2")
            uci:set("ca_setup", "ocn_static_map", hotplug_key, "1")
            uci:commit("ca_setup")
            log_message("OCN Virtual Connect MAP-E hotplug handler registered")
            local rc_check_cmd = string.format("grep -F '%s -s2' %s >/dev/null 2>&1", script_path, rcLocalPath)
            if os.execute(rc_check_cmd) ~= 0 then
                log_message("Startup entry for -s2 missing; registering static MAP-E boot hook.")
                reg_map_startup_static()
            end
        else
            log_message("OCN MAP-E hotplug handler already installed; skipping setup")
        end

        script_lock_disable()
        save_logs_to_persistent_storage()
        os.exit(0)


    elseif mode == "-s4" then
        -- transix Static IP IPIP connection setup module
        log_message("----------------------------------------------")
        log_message("   transix Static IP IPIP connection setup     ")
        log_message("----------------------------------------------")
        local current_time = os.date("%Y-%m-%d %H:%M:%S")
        log_message("timestamp: " .. current_time)
        wan6_interface = get_ifname("wan6")
        wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()
        local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
        local cur_prefix64 = cur_wan_state.prefix64
        update_wan6_cur_prefix(cur_wan_state)
        urkey, brandcheck, sysinfo_model = brand_status()

        -- Get parameters
        local from_hotplug = arg[2] == "--from-hotplug"
        local ipv6_remote = from_hotplug and nil or arg[2]
        local ipv6_ifaceid = from_hotplug and nil or arg[3]
        local ipv4_addr   = from_hotplug and nil or arg[4]
        local user_id     = from_hotplug and nil or arg[5]
        local user_pass   = from_hotplug and nil or arg[6]

        -- Use saved values when called from hotplug or if parameters are missing
        if from_hotplug or not (ipv6_remote and ipv6_ifaceid and ipv4_addr and user_id and user_pass) then
            ipv6_remote = uci:get("ca_setup", "transix_ipip", "ipv6_remote")
            ipv6_ifaceid = uci:get("ca_setup", "transix_ipip", "ipv6_ifaceid")
            ipv4_addr = uci:get("ca_setup", "transix_ipip", "ipv4_addr")
            user_id = decryptedData(uci:get("ca_setup", "transix_ipip", "user_id"))
            user_pass = decryptedData(uci:get("ca_setup", "transix_ipip", "user_pass"))
            if not (ipv6_remote and ipv6_ifaceid and ipv4_addr and user_id and user_pass) then
                log_message("ERROR: Required parameters are missing")
                save_logs_to_persistent_storage()
                os.exit(1)
            end
        else
            -- Save on first run
            uci:section("ca_setup", "settings", "transix_ipip", {
                ipv6_remote = ipv6_remote,
                ipv6_ifaceid = ipv6_ifaceid,
                ipv4_addr = ipv4_addr,
                user_id = encrypt_data(user_id, urkey),
                user_pass = encrypt_data(user_pass, urkey),
                last_wan_sig = cur_wan_state.sig,
                setup_time = os.time()
            })
            uci:commit("ca_setup")
            log_message("Saved transix IPIP authentication information")
        end

        -- Only re-execute on prefix change
        if should_skip_hotplug_reconfig("transix_ipip", cur_wan_state, from_hotplug) then
            save_logs_to_persistent_storage()
            os.exit(0)
        end

        -- Notify transix update server
        local update_url = string.format(
            "http://update.transix.jp/request?username=%s&password=%s",
            urlencode(user_id), urlencode(user_pass)
        )
        local handle = io.popen("curl -s -w '\\nHTTP_STATUS:%{http_code}\\n' " .. shellquote(update_url))
        local result = handle:read("*a")
        handle:close()
        local body, code = result:match("^([%s%S]*)\nHTTP_STATUS:(%d+)\n?$")
        log_message("transix update server response: " .. (body or "") .. " (HTTP " .. (code or "") .. ")")

        if tonumber(code) ~= 200 or not body:find("OK") then
            log_message("ERROR: Failed to notify update server")
            save_logs_to_persistent_storage()
            os.exit(1)
        end

        -- Apply configuration
        save_last_wan_state("transix_ipip", cur_wan_state)
        uci:set("ca_setup", "transix_ipip", "setup_time", os.time())
        uci:commit("ca_setup")

        -- IPIP interface configuration
        local ipv6_local = concat_ipv6_prefix_and_ifaceid(ipv6_56, ipv6_ifaceid)
        clean_wan_configuration()
        tune_sysctl(ipv6_fixlen, under_router)
        configure_ipip_connection(ipv4_addr, ipv6_local, ipv6_remote, ipv6_ifaceid, ipv6_fixlen, ipv6_56)
        network_restart_handler("IPIP configuration", 60)
        check_internet_connectivity()

        -- Set up hotplug script (only on first run)
        if not from_hotplug then
            log_message("Setting up transix IPIP hotplug handler with prefix detection...")
            setup_ipip_prefix_hotplug("s4")
            log_message("transix IPIP setup completed")
            save_logs_to_persistent_storage()
        else
            log_message("transix IPIP setup completed (from hotplug), rebooting router...")
            save_logs_to_persistent_storage()
            os.execute("sleep 5")
            reboot_system()
        end


    elseif mode == "-s5" then
        -- Asahi Net IPIP connection setup routine 
        log_message("----------------------------------------------")
        log_message("   Asahi Net IPIP connection setup routine    ")
        log_message("----------------------------------------------")
        local current_time = os.date("%Y-%m-%d %H:%M:%S")
        log_message("timestamp: " .. current_time)
        wan6_interface = get_ifname("wan6")
        wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status() 
        local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
        local cur_prefix64 = cur_wan_state.prefix64
        update_wan6_cur_prefix(cur_wan_state)
        urkey, brandcheck, sysinfo_model = brand_status()
        
        -- Get username and password - either from arguments or saved credentials
        local from_hotplug = arg[2] == "--from-hotplug"
        local username = from_hotplug and nil or arg[2]
        local password = from_hotplug and nil or arg[3]
        
        -- If called from hotplug or credentials not provided, try to load saved credentials
        if from_hotplug or not username or not password then
            -- Check for saved credentials
            local encrypted_username = uci:get("ca_setup", "ipip", "username")
            local encrypted_password = uci:get("ca_setup", "ipip", "password")
            
            if encrypted_username and encrypted_password then
                log_message("Using saved credentials for IPIP authentication")
                username = decryptedData(encrypted_username)
                password = decryptedData(encrypted_password)
            else
                log_message("ERROR: No credentials provided and no saved credentials found")
                save_logs_to_persistent_storage()
                os.exit(1)
            end
        else
            -- Save credentials for future use (hotplug reconnections)
            local encrypted_username = encrypt_data(username, urkey)
            local encrypted_password = encrypt_data(password, urkey)
            
            -- Save credentials
            uci:section("ca_setup", "settings", "ipip", {
                username = encrypted_username,
                password = encrypted_password,
                last_wan_sig = cur_wan_state.sig,
                setup_time = os.time()
            })
            uci:commit("ca_setup")
            log_message("Saved IPIP authentication information for future use")
        end
        
        -- Check if IPv6 prefix has changed (only relevant for hotplug calls)
        if should_skip_hotplug_reconfig("ipip", cur_wan_state, from_hotplug) then
            save_logs_to_persistent_storage()
            os.exit(0)
        end

        log_message("Retrieving Asahi Net IPIP connection information...")
        local code, data = v6mig_call(username, password)

        if not code or not data or data.error then
            log_message("ERROR: Failed to retrieve IPIP configuration")
            log_message("Status code: " .. (code or "nil"))
            log_message("Error: " .. (data and data.error or "unknown error"))
            save_logs_to_persistent_storage()
            os.exit(1)
        end
        
        -- Extract IPIP information
        local ipip_data = {}
        if data.ipip and type(data.ipip) == "table" and #data.ipip > 0 then
            ipip_data = data.ipip[1]
        end
        local ipv4_addr = ipip_data.ipv4 or "nil"
        if ipv4_addr ~= "nil" then
            local ipv4_obj = ip.IPv4(ipv4_addr)
            if ipv4_obj then
                ipv4_addr = ipv4_obj:host():string()
            end
        end
        local ipv6_local = ipip_data.ipv6_local or "nil"
        local ipv6_remote = ipip_data.ipv6_remote or "nil"
        
        -- Update saved WAN /64 state
        save_last_wan_state("ipip", cur_wan_state)
        uci:set("ca_setup", "ipip", "setup_time", os.time())
        uci:commit("ca_setup")
        
        -- Create structured output
        local asahi_ipip_data = {
            asahi_ipip = {
                ipv4_addr = ipv4_addr,
                ipv6_local = ipv6_local,
                ipv6_remote = ipv6_remote,
                auth_success = (tonumber(code) == 200 and data.auth == "ok")
            }
        }
        
        -- Output JSON response
        local json_output = json.stringify(asahi_ipip_data, true)
        log_message(json_output)

        local ipv6_ifaceid = extract_ipv6_ifaceid(ipv6_local)

        -- Proceed with IPIP connection setup
        clean_wan_configuration()  
        tune_sysctl(ipv6_fixlen, under_router) 
        configure_ipip_connection(ipv4_addr, ipv6_local, ipv6_remote, ipv6_ifaceid, ipv6_fixlen, ipv6_56)
        network_restart_handler("IPIP configuration", 60)
        check_internet_connectivity()
        
        -- Set up hotplug script for IPv6 prefix change detection
        -- Only do this on initial setup, not during a hotplug-triggered reconnection
        if not from_hotplug then
            log_message("Setting up IPIP hotplug handler with prefix detection...")
            setup_ipip_prefix_hotplug("s5")
            log_message("IPIP setup completed")
            save_logs_to_persistent_storage()
        else
            log_message("IPIP setup completed (from hotplug), rebooting router...")
            save_logs_to_persistent_storage()
            os.execute("sleep 5")
            reboot_system()
        end


    elseif mode == "-s6" then
        -- Xpass (Arteria) Static IP IPIP connection setup routine
        log_message("----------------------------------------------")
        log_message("   Xpass (Arteria) Static IP IPIP Setup        ")
        log_message("----------------------------------------------")
        local current_time = os.date("%Y-%m-%d %H:%M:%S")
        log_message("timestamp: " .. current_time)
        wan6_interface = get_ifname("wan6")
        wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()
        local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
        local cur_prefix64 = cur_wan_state.prefix64
        update_wan6_cur_prefix(cur_wan_state)
        urkey, brandcheck, sysinfo_model = brand_status()

        -- Receive parameters
        local from_hotplug   = arg[2] == "--from-hotplug"
        local fqdn           = from_hotplug and nil or arg[2]
        local ddns_id        = from_hotplug and nil or arg[3]
        local ddns_password  = from_hotplug and nil or arg[4]
        local basic_id       = from_hotplug and nil or arg[5]
        local basic_pass     = from_hotplug and nil or arg[6]
        local ddns_url       = from_hotplug and nil or arg[7]
        local ipv6_remote    = from_hotplug and nil or arg[8]
        local ipv4_addr      = from_hotplug and nil or arg[9]

        -- Load saved config if called from hotplug or missing params
        if from_hotplug or not (fqdn and ddns_id and ddns_password and basic_id and basic_pass and ddns_url and ipv6_remote and ipv4_addr) then
            fqdn          = uci:get("ca_setup", "xpass_ipip", "fqdn")
            ddns_id       = uci:get("ca_setup", "xpass_ipip", "ddns_id")
            ddns_password = decryptedData(uci:get("ca_setup", "xpass_ipip", "ddns_password"))
            basic_id      = decryptedData(uci:get("ca_setup", "xpass_ipip", "basic_id"))
            basic_pass    = decryptedData(uci:get("ca_setup", "xpass_ipip", "basic_pass"))
            ddns_url      = uci:get("ca_setup", "xpass_ipip", "ddns_url")
            ipv6_remote   = uci:get("ca_setup", "xpass_ipip", "ipv6_remote")
            ipv4_addr     = uci:get("ca_setup", "xpass_ipip", "ipv4_addr")
            if not (fqdn and ddns_id and ddns_password and basic_id and basic_pass and ddns_url and ipv6_remote and ipv4_addr) then
                log_message("ERROR: Required parameters are missing")
                save_logs_to_persistent_storage()
                os.exit(1)
            end
        else
            -- Save config for future hotplug use
            uci:section("ca_setup", "settings", "xpass_ipip", {
                fqdn          = fqdn,
                ddns_id       = ddns_id,
                ddns_password = encrypt_data(ddns_password, urkey),
                basic_id      = encrypt_data(basic_id, urkey),
                basic_pass    = encrypt_data(basic_pass, urkey),
                ddns_url      = ddns_url,
                ipv6_remote   = ipv6_remote,
                ipv4_addr     = ipv4_addr,
                last_wan_sig  = cur_wan_state.sig,
                setup_time    = os.time()
            })
            uci:commit("ca_setup")
            log_message("Saved Xpass IPIP authentication and DDNS information")
        end

        -- Only re-execute on prefix change
        if should_skip_hotplug_reconfig("xpass_ipip", cur_wan_state, from_hotplug) then
            save_logs_to_persistent_storage()
            os.exit(0)
        end

        -- Update saved prefix
        save_last_wan_state("xpass_ipip", cur_wan_state)
        uci:set("ca_setup", "xpass_ipip", "setup_time", os.time())
        uci:commit("ca_setup")

        -- Write DDNS config for OpenWrt ddns-scripts
        local ddns_config_path = "/etc/config/ddns"
        local ddns_update_url = string.format(
            "%s://%s:%s@%s?d=%s&p=%s&a=[IP]&u=%s",
            ddns_url:match("^https") and "https" or "http",
            basic_id, basic_pass,
            ddns_url:gsub("^https?://", ""), 
            ddns_id, ddns_password, ddns_id
        )
        local ddns_section = string.format([[
        config service 'arteria_ddns'
            option enabled '1'
            option use_ipv6 '1'
            option lookup_host '%s'
            option domain '%s'
            option username '%s'
            option password '%s'
            option interface 'wan6'
            option ip_source 'interface'
            option ip_interface 'br-lan'
            option update_url '%s'
            option use_https '1'
            option cacert 'IGNORE'
        ]], fqdn, ddns_id, basic_id, basic_pass, ddns_update_url)

        -- Overwrite ddns config (or you may want to merge if multiple services)
        local f = io.open(ddns_config_path, "w")
        if f then
            f:write(ddns_section)
            f:close()
            log_message("Wrote DDNS config to " .. ddns_config_path)
        else
            log_message("ERROR: Failed to write DDNS config")
            save_logs_to_persistent_storage()
            os.exit(1)
        end

        -- Restart ddns service to notify new IPv6 prefix
        os.execute("/etc/init.d/ddns restart")
        log_message("Restarted ddns service for IPv6 update notification")

        -- Wait for DDNS update to propagate (optional: check log or status)
        os.execute("sleep 10")

        -- Proceed with IPIP tunnel setup (tunnel config itself is not shown here)
        clean_wan_configuration()
        tune_sysctl(ipv6_fixlen, under_router)
        local ipv6_local = concat_ipv6_prefix_and_ifaceid(ipv6_56, "::1")
        -- For XPass IPIP, the interface ID is fixed to ::1 for both WAN6 and LAN
        local ipv6_ifaceid = "::1"
        configure_ipip_connection(ipv4_addr, ipv6_local, ipv6_remote, ipv6_ifaceid, ipv6_fixlen, ipv6_56)
        network_restart_handler("IPIP configuration", 60)
        check_internet_connectivity()

        -- Setup hotplug script for prefix change detection (DDNS update will be triggered by ddns-scripts)
        if not from_hotplug then
            log_message("Setting up Xpass IPIP hotplug handler with prefix detection...")
            setup_ipip_prefix_hotplug("s6")
            log_message("Xpass IPIP setup completed")
            save_logs_to_persistent_storage()
        else
            log_message("Xpass IPIP setup completed (from hotplug), rebooting router...")
            save_logs_to_persistent_storage()
            os.execute("sleep 5")
            reboot_system()
        end


    elseif mode == "-s7" then
        -- OCX Hikari v6IX IPIP connection setup routine
        log_message("----------------------------------------------")
        log_message("   OCX Hikari v6IX IPIP connection setup      ")
        log_message("----------------------------------------------")
        local current_time = os.date("%Y-%m-%d %H:%M:%S")
        log_message("timestamp: " .. current_time)
        wan6_interface = get_ifname("wan6")
        wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()
        local cur_wan_state = get_current_wan_state(wan_ipv6, ipv6Prefix, prefixLength)
        local cur_prefix64 = cur_wan_state.prefix64
        update_wan6_cur_prefix(cur_wan_state)
        urkey, brandcheck, sysinfo_model = brand_status()

        -- v6mig_callで情報取得（認証不要）
        log_message("Retrieving OCX Hikari v6IX IPIP connection information...")
        local code, data = v6mig_call()

        if not code or not data or data.error then
            log_message("ERROR: Failed to retrieve IPIP configuration")
            log_message("Status code: " .. (code or "nil"))
            log_message("Error: " .. (data and data.error or "unknown error"))
            save_logs_to_persistent_storage()
            os.exit(1)
        end

        -- Extract IPIP information
        local ipip_data = {}
        if data.ipip and type(data.ipip) == "table" and #data.ipip > 0 then
            ipip_data = data.ipip[1]
        end
        local ipv4_addr = ipip_data.ipv4 or "nil"
        if ipv4_addr ~= "nil" then
            local ipv4_obj = ip.IPv4(ipv4_addr)
            if ipv4_obj then
                ipv4_addr = ipv4_obj:host():string()
            end
        end
        local ipv6_local = ipip_data.ipv6_local or "nil"
        local ipv6_remote = ipip_data.ipv6_remote or "nil"

        -- Update saved WAN /64 state
        save_last_wan_state("ipip", cur_wan_state)
        uci:set("ca_setup", "ipip", "setup_time", os.time())
        uci:commit("ca_setup")

        -- Create structured output
        local ocx_ipip_data = {
            ocx_ipip = {
                ipv4_addr = ipv4_addr,
                ipv6_local = ipv6_local,
                ipv6_remote = ipv6_remote,
                auth_success = (tonumber(code) == 200)
            }
        }

        -- Output JSON response
        local json_output = json.stringify(ocx_ipip_data, true)
        log_message(json_output)

        local ipv6_ifaceid = extract_ipv6_ifaceid(ipv6_local)

        -- Proceed with IPIP connection setup
        clean_wan_configuration()
        tune_sysctl(ipv6_fixlen, under_router)
        configure_ipip_connection(ipv4_addr, ipv6_local, ipv6_remote, ipv6_ifaceid, ipv6_fixlen, ipv6_56)
        network_restart_handler("IPIP configuration", 60)
        check_internet_connectivity()

        -- Set up hotplug script for IPv6 prefix change detection
        -- Only do this on initial setup, not during a hotplug-triggered reconnection
        if not (arg[2] == "--from-hotplug") then
            log_message("Setting up IPIP hotplug handler with prefix detection...")
            setup_ipip_prefix_hotplug("s7")
            log_message("IPIP setup completed")
            save_logs_to_persistent_storage()
        else
            log_message("IPIP setup completed (from hotplug), rebooting router...")
            save_logs_to_persistent_storage()
            os.execute("sleep 5")
            reboot_system()
        end

    elseif mode == "-disable" then
            -- disable auto_ipoe execution
                log_message("autoipoe disable routine")
                uci:delete("ca_setup", "map")
                uci:commit("ca_setup")
                unreg_map_startup()
                remove_cron_entry()
                log_message("Disabled mapv6 hotplug, schedule, and execution on reboot")
                save_logs_to_persistent_storage()

    elseif mode == "-enable" then
            -- enable auto_ipoe execution  
            log_message("autoipoe enable routine") 
            local cron_entry = uci:get("ca_setup", "map", "cron_entry")
            if cron_entry == nil then 
                reg_map_startup()
                check_cron_entry()
                check_wan_hotplug()
                log_message("Enabled mapv6 hotplug, schedule, and execution on reboot")
                save_logs_to_persistent_storage()
            else
                log_message("mapv6 hotplug, schedule, and execution on reboot are already enabled")
                save_logs_to_persistent_storage()
            end   

    elseif mode == "-encrypt" then
            -- Debug helper: encrypt arbitrary text with device key
            local input_text = arg[2]
            if not input_text or input_text == "" then
                io.write("Enter text to encrypt: ")
                input_text = io.read("*l")
            end
            if not input_text or input_text == "" then
                print("No text provided; aborting.")
                os.exit(1)
            end
            local urkey = brand_status()
            local encrypted = encrypt_data(input_text, urkey)
            print("Encrypted text:")
            print(encrypted)

    elseif mode == "-ip" and arg[2]  then
            urkey, brandcheck, sysinfo_model = brand_status()
            wan_ipv6 = arg[2] 
            ipv6_56 = extract_ipv6_56(wan_ipv6)
            ipv6_fixlen = 64
            local peeraddr, ipv4_prefix, ipv4_prefixlen, ipv6_prefix, ipv6_prefixlen, ealen, psidlen, offset, ipv6_fixlen, ipv6_56, fmr, fmr_json, wan_ipv6, wan32_ipv6, wan40_ipv6 = get_mapconfig(wan_ipv6, ipv6_56, ipv6_fixlen)
                 local matching_fmr_data = {
                    matching_fmr = {
                        peeraddr = peeraddr or "nil",
                        ipv4_prefix = ipv4_prefix or "nil",
                        ipv4_prefixlen = ipv4_prefixlen or "nil",
                        ipv6_prefix = ipv6_prefix or "nil",
                        ipv6_prefixlen = ipv6_prefixlen or "nil",
                        ealen = ealen or "nil",
                        psidlen = psidlen or "nil",
                        offset = offset or "nil",
                        ipv6_fixlen = ipv6_fixlen or "nil",
                        ipv6_56 = ipv6_56 or "nil"
                    }
                }
                
                local json_output = json.stringify(matching_fmr_data, true)
                
                log_message(json_output)
              
    elseif mode == "-h" then
            print("available parameters")
            print("-h: help")
            print("-m1: v6 Plus")
            print("-m2: OCN Virtual Connect")
            print("-m3: IPv6 Option")
            print("-s5: Asahi Net IPIP (requires username password)")
            print("-enable: auto_ipoe")
            print("-disable: auto_ipoe")
            print("-nohgw: debug mode to bypass router detection")
            print("-duplicate: check for duplicate CE / map-e BR")
            print("-check_internet: run internet connectivity test in debug mode")
            print("-ver: software version")

    elseif mode == "-ver" then
            print("Linksys Japan NTT IPv4 over IPv6 Config Program ver 1.6")

    elseif mode == "-duplicate" then
        -- Simple debug mode for duplicate CE detection
        log_message("Running duplicate CE detection in debug mode...")
        
        -- Get WAN IPv6 info using existing function
        local wan_ipv6, ipv6Prefix, prefixLength, route_target, route_mask, ipv6_56, ipv6_fixlen = getIPv6_wan_status()
        log_message("WAN IPv6: " .. wan_ipv6)
        log_message("IPv6 prefix: " .. ipv6_56)
        
        -- Get interface name
        local wan6_interface = get_ifname("wan6")
        log_message("WAN6 interface: " .. wan6_interface)
        
        -- Run the detection with proper parameters
        local duplicate_detected = detect_duplicate_ce(wan6_interface, ipv6_56)
        
        if duplicate_detected then
            log_message("RESULT: Duplicate CE DETECTED!")
            save_logs_to_persistent_storage()
            os.exit(1)
        else
            log_message("RESULT: No duplicate CE detected")
            save_logs_to_persistent_storage()
            os.exit(0)
        end

    elseif mode == "-nohgw" then
        -- Debug mode that bypasses router detection
        debug_nohgw = 1
        log_message("Debug mode: Router detection bypassed (-nohgw). Forcing nder_router=3")
        main()

    elseif mode == "-check_internet" then
        log_message("Running internet connectivity check in debug mode...")
        
        -- Get WAN interface info for reference
        local wan_interface = get_ifname("wan")
        local wan6_interface = get_ifname("wan6")
        log_message("WAN interfaces: IPv4=" .. wan_interface .. ", IPv6=" .. wan6_interface)
        
        -- Show current IP configuration
        log_message("Current IPv4 configuration:")
        local ipv4_cmd = "ip addr show dev " .. wan_interface .. " 2>&1"
        local handle = io.popen(ipv4_cmd)
        local ipv4_output = handle:read("*a")
        handle:close()
        log_message(ipv4_output)
        
        log_message("Current IPv6 configuration:")
        local ipv6_cmd = "ip -6 addr show dev " .. wan6_interface .. " 2>&1"
        handle = io.popen(ipv6_cmd)
        local ipv6_output = handle:read("*a")
        handle:close()
        log_message(ipv6_output)
        
        -- Show current routing table
        log_message("Current IPv4 routing table:")
        handle = io.popen("ip route")
        local route_output = handle:read("*a")
        handle:close()
        log_message(route_output)
        
        log_message("Current IPv6 routing table:")
        handle = io.popen("ip -6 route")
        local route6_output = handle:read("*a")
        handle:close()
        log_message(route6_output)
        
        -- Run DNS resolution test
        log_message("Testing DNS resolution:")
        handle = io.popen("nslookup google.com 2>&1")
        local dns_output = handle:read("*a")
        handle:close()
        log_message(dns_output)
        
        -- Run the connectivity check in debug mode
        local connectivity_result = check_internet_connectivity(true)
        
        -- Summarize result
        if connectivity_result then
            log_message("RESULT: Internet connectivity check PASSED")
            save_logs_to_persistent_storage()
            os.exit(0)
        else
            log_message("RESULT: Internet connectivity check FAILED")
            save_logs_to_persistent_storage()
            os.exit(1)
        end

    elseif mode == "-v6mig" then
        -- v6mig debug mode - test v6mig service and output JSON response
        log_message("Running v6mig debug mode...")
        
        -- Show current system info
        log_message("System information:")
        log_message("MAC OUI detection:")
        local oui = sys.exec("ip link | grep -o -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | grep -v '00:00:00:00:00:00' | head -n1 | awk -F: '{print tolower($1$2$3)}'")
        if oui then oui = oui:match("^%s*(%x%x%x%x%x%x)%s*$") or "" end
        local vendorid = (#oui == 6) and oui or "acde48"
        log_message("Detected OUI: " .. (oui or "none") .. " -> Vendor ID: " .. vendorid)
        
        -- Show DNS lookup for service URL
        log_message("DNS lookup for v6mig service:")
        local dns = sys.exec("nslookup -type=txt 4over6.info 2>/dev/null")
        local url = dns:match('text%s*=%s*"[^"]*url=([^%s"]+)')
        log_message("DNS TXT record: " .. (dns or "none"))
        log_message("Extracted URL: " .. (url or "none"))
        
        -- Check for existing token/TTL
        local function readfile(path)
            local f = io.open(path, "r")
            if f then local data = f:read("*a"):gsub("\n", "") f:close() return data end
        end
        
        local token = readfile("/etc/prov_token")
        local ttl = readfile("/etc/prov_ttl")
        log_message("Existing token: " .. (token and "exists" or "none"))
        log_message("Token TTL: " .. (ttl or "none") .. " (current time: " .. os.time() .. ")")
        
        -- Test v6mig service without authentication
        log_message("Testing v6mig service without authentication...")
        local code1, data1 = v6mig()
        log_message("v6mig() result:")
        log_message("HTTP Code: " .. (code1 or "nil"))
        if data1 then
            local json_output1 = json.stringify(data1, true)
            log_message("JSON Response:")
            log_message(json_output1)
            local gw_aftr1 = data1.aftr or data1.gateway or data1.gw_aftr
            if gw_aftr1 then
                log_message("Extracted gw_aftr: " .. gw_aftr1)
            end
        else
            log_message("No data returned")
        end
        
        -- Test v6mig_call wrapper
        log_message("Testing v6mig_call() wrapper with retry logic...")
        local code2, data2 = v6mig_call()
        log_message("v6mig_call() result:")
        log_message("HTTP Code: " .. (code2 or "nil"))
        if data2 then
            local json_output2 = json.stringify(data2, true)
            log_message("JSON Response:")
            log_message(json_output2)
            local gw_aftr2 = data2.aftr or data2.gateway or data2.gw_aftr
            if gw_aftr2 then
                log_message("Extracted gw_aftr: " .. gw_aftr2)
            end
        else
            log_message("No data returned")
        end
        
        -- Show final token/TTL state
        local final_token = readfile("/etc/prov_token")
        local final_ttl = readfile("/etc/prov_ttl")
        log_message("Final token: " .. (final_token and "exists" or "none"))
        log_message("Final TTL: " .. (final_ttl or "none"))
        
        log_message("v6mig debug mode completed")
        save_logs_to_persistent_storage()


    else
            log_message("Unknown argument: " .. args[1])
            save_logs_to_persistent_storage()
    end
else
    main() -- Execute the main script if there are no arguments
end
