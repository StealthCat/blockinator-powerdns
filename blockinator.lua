-- PowerDNS Recursor DNS hook. Restart Recursor after first enabling this script
-- to discard existing packet-cache entries. Do not use as lua-config-file.
local bridge = newCA("127.0.0.1:53001")
local failMode = "open" -- "open": resolve normally; "closed": SERVFAIL
assert(failMode == "open" or failMode == "closed")

local function unavailable(dq)
    if failMode == "closed" then
        dq.rcode = pdns.SERVFAIL
        return true
    end
    return false
end

function blockinatorResponse(dq)
    dq.followupFunction = ""
    local action = dq.udpAnswer
    if action == "allow" then return false end
    if action == "nxdomain" then
        dq.rcode = pdns.NXDOMAIN
    elseif action == "refused" then
        dq.rcode = pdns.REFUSED
    elseif action == "nodata" or action == "zero" then
        dq.rcode = pdns.NOERROR
        if action == "zero" then
            if dq.qtype == pdns.A then dq:addAnswer(pdns.A, "0.0.0.0", 0) end
            if dq.qtype == pdns.AAAA then dq:addAnswer(pdns.AAAA, "::", 0) end
        end
    else
        -- Includes empty replies when the bridge is stopped or unreachable.
        return unavailable(dq)
    end
    return true
end

function preresolve(dq)
    -- Both allowed and blocked answers depend on client and current policy.
    -- Recursor's record cache remains available for normal resolution.
    dq.variable = true
    local hexName = dq.qname:toString():gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end)
    dq.udpQuery = table.concat({"v1", dq.remoteaddr:toString(),
        tostring(dq.remoteaddr:getPort()), dq.isTcp and "tcp" or "udp",
        tostring(dq.qtype), hexName}, "\n")
    dq.udpQueryDest = bridge
    dq.udpCallback = "blockinatorResponse"
    dq.followupFunction = "udpQueryResponse"
    return true
end
