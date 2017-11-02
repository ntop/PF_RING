--
-- (C) 2017 - ntop.org
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU Lessed General Public License as published by
-- the Free Software Foundation; either version 2.1 of the License, or
-- (at your option) any later version.
--


-- create myproto protocol and its fields
p_pfringflow = Proto("PFRingFlow", "PF_RING Flow Offload Record")

local f_flow_id = ProtoField.uint32("pfringflow.flow_id", "Flow Id", base.DEC)
local f_ip_version = ProtoField.uint8("pfringflow.ip_version", "IP Version", base.DEC)
local f_l4_protocol = ProtoField.uint8("pfringflow.l4_protocol", "L4 Protocol", base.DEC)
local f_tos = ProtoField.uint8("pfringflow.tos", "TOS", base.DEC)
local f_tcp_flags = ProtoField.uint8("pfringflow.tcp_flags", "TCP Flags", base.DEC)
local f_src_ipv4 = ProtoField.ipv4("pfringflow.src_ipv4", "IPv4 Src Address")
local f_src_ipv6 = ProtoField.ipv6("pfringflow.src_ipv6", "IPv6 Src Address")
local f_dst_ipv4 = ProtoField.ipv4("pfringflow.dst_ipv4", "IPv4 Dst Address")
local f_dst_ipv6 = ProtoField.ipv6("pfringflow.dst_ipv6", "IPv6 Dst Address")
local f_src_port = ProtoField.uint16("pfringflow.src_port", "Source Port", base.DEC)
local f_dst_port = ProtoField.uint16("pfringflow.dst_port", "Destination Port", base.DEC)
local f_fwd_packets = ProtoField.uint32("pfringflow.fwd_packets", "Forward Packets", base.DEC)
local f_fwd_bytes = ProtoField.uint32("pfringflow.fwd_bytes", "Forward Bytes", base.DEC)
local f_rev_packets = ProtoField.uint32("pfringflow.rev_packets", "Reverse Packets", base.DEC)
local f_rev_bytes = ProtoField.uint32("pfringflow.rev_bytes", "Reverse Bytes", base.DEC)
  -- Timestamp format: (sec << 32) | (nsec)
local f_fwd_ts_first = ProtoField.string("pfringflow.fwd_ts_first", "Forward First Seen")
local f_fwd_ts_last = ProtoField.string("pfringflow.fwd_ts_last", "Forward Last Seen")
local f_rev_ts_first = ProtoField.string("pfringflow.rev_ts_first", "Reverse First Seen")
local f_rev_ts_last = ProtoField.string("pfringflow.rev_ts_last", "Reverse Last Seen")


p_pfringflow.fields = { f_flow_id, f_ip_version, f_l4_protocol, f_tos, f_tcp_flags,
		      f_src_ipv4, f_src_ipv6, f_dst_ipv4, f_dst_ipv6,
		      f_src_port, f_dst_port, f_fwd_packets, f_fwd_bytes, f_rev_packets, f_rev_bytes,
		      f_fwd_ts_first, f_fwd_ts_last, f_rev_ts_first, f_rev_ts_last
}



-- Accolade dissector function
function p_pfringflow.dissector (buf, pkt, root)
   local sec, nsec, sec_offset
   -- NOTE:
   -- buf(A, B) => A = offset,  b = lenght
   -- subtree:add => big endian, subtree:add_le => little endian
   --

   -- validate packet length is adequate, otherwise quit
   if buf:len() == 0 then return end
   pkt.cols.protocol = p_pfringflow.name

   -- create subtree for pfringflow
   subtree = root:add(p_pfringflow, buf(0))
   offset = 0

   -- add protocol fields to subtree
   subtree:add_le(f_flow_id, buf(offset, 4))
   offset = offset + 4

   subtree:add(f_ip_version, buf(offset, 1))
   offset = offset + 1

   subtree:add(f_l4_protocol, buf(offset, 1))
   offset = offset + 1

   subtree:add(f_tos, buf(offset, 1))
   offset = offset + 1

   subtree:add(f_tcp_flags, buf(offset, 1))
   offset = offset + 1

   if(buf(4,1):uint() == 4) then
      subtree:add_le(f_src_ipv4, buf(offset, 4))
      offset = offset + 16
      subtree:add_le(f_dst_ipv4, buf(offset, 4))
      offset = offset + 16
   else
      subtree:add_le(f_src_ipv6, buf(offset, 16))
      offset = offset + 16
      subtree:add_le(f_dst_ipv6, buf(offset, 16))
      offset = offset + 16
   end

   subtree:add_le(f_src_port, buf(offset, 2))
   offset = offset + 2

   subtree:add_le(f_dst_port, buf(offset, 2))
   offset = offset + 2

   subtree:add_le(f_fwd_packets, buf(offset, 4))
   offset = offset + 4

   subtree:add_le(f_fwd_bytes, buf(offset, 4))
   offset = offset + 4

   subtree:add_le(f_rev_packets, buf(offset, 4))
   offset = offset + 4

   subtree:add_le(f_rev_bytes, buf(offset, 4))
   offset = offset + 4

   -- Fwd
   sec_offset = offset
   sec = buf(offset, 4):le_uint()
   offset = offset + 4

   nsec = buf(offset, 4):le_uint()
   offset = offset + 4

   subtree:add(f_fwd_ts_first, buf(sec_offset, 8), sec.."."..nsec)

   sec_offset = offset
   sec = buf(offset, 4):le_uint()
   offset = offset + 4

   nsec = buf(offset, 4):le_uint()
   offset = offset + 4

   subtree:add(f_fwd_ts_last, buf(sec_offset, 8), sec.."."..nsec)

   -- Rev
   sec_offset = offset
   sec = buf(offset, 4):le_uint()
   offset = offset + 4

   nsec = buf(offset, 4):le_uint()
   offset = offset + 4

   subtree:add(f_rev_ts_first, buf(sec_offset, 8), sec.."."..nsec)

   sec_offset = offset
   sec = buf(offset, 4):le_uint()
   offset = offset + 4

   nsec = buf(offset, 4):le_uint()
   offset = offset + 4

   subtree:add(f_rev_ts_last, buf(sec_offset, 8), sec.."."..nsec)

end

-- Initialization routine
function p_pfringflow.init()
end

-- 0x0F00 = 61440
local eth_dissector_table = DissectorTable.get("ethertype")
dissector = eth_dissector_table:get_dissector(61440)
-- you can call dissector from function p_pfringflow.dissector above
-- so that the previous dissector gets called
eth_dissector_table:add(61440, p_pfringflow)
