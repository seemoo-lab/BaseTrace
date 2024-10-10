--[[
Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.3

Copyright (c) 2022 Lukas Arnold <lukas.arnold@stud.tu-darmstadt.de>

Based on:

- Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.2
  Copyright (c) 2017 Daniele Palmas <dnlplm@gmail.com>
  available at: https://github.com/dnlplm/WiresharkQMIDissector

- Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.1
  Copyright (c) 2012 Ilya Voronin <ivoronin@gmail.com>
  available at: https://gist.github.com/ivoronin/2641557

- Code Aurora Forum's BSD/GPL licensed code:
  http://www.codeaurora.org/contribute/projects/gobi/

- freedesktop.org libqmi
  https://www.freedesktop.org/wiki/Software/libqmi/
--]]

---
--- Proto declaration
---

qmi_proto = Proto("qmi", "Qualcomm MSM Interface")

--
-- Fields
--

-- QMI fields

local f = qmi_proto.fields

-- QMUX Header
f.tf = ProtoField.uint8("qmi.tf", "T/F", base.DEC)
f.len = ProtoField.uint16("qmi.len", "Length", base.DEC)
f.flag = ProtoField.uint8("qmi.flag", "Flag", base.HEX)
f.cid = ProtoField.uint8("qmi.client_id", "Client ID", base.HEX)
-- Transaction Header
f.resp_ctl = ProtoField.uint8("qmi.trans_response", "Transaction Response Bit",
		base.DEC, nil, 1)
f.ind_ctl = ProtoField.uint8("qmi.trans_indication", "Transaction Indication Bit",
		base.DEC, nil, 2)
f.comp_svc = ProtoField.uint8("qmi.trans_compound", "Transaction Compound Bit",
		base.DEC, nil, 1)
f.resp_svc = ProtoField.uint8("qmi.trans_response", "Transaction Response Bit",
		base.DEC, nil, 2)
f.ind_svc = ProtoField.uint8("qmi.trans_indication", "Transaction Indication Bit",
		base.DEC, nil, 4)
f.tid_ctl = ProtoField.uint8("qmi.trans_id", "Transaction ID", base.HEX)
f.tid_svc = ProtoField.uint16("qmi.trans_id", "Transaction ID", base.HEX)
-- Message Header
f.msgid = ProtoField.uint16("qmi.message_id", "Message ID", base.HEX)
f.indid = ProtoField.uint16("qmi.indication_id", "Indication ID", base.HEX)


-- GENERATE(QMI_MESSAGE_STRUCTURES)


f.msglen = ProtoField.uint16("qmi.message_len", "Message Length", base.DEC)
-- TLVs
f.tlvt = ProtoField.uint8("qmi.tlv_type", "TLV Type", base.HEX)
f.tlvl = ProtoField.uint16("qmi.tlv_len", "TLV Length", base.DEC)
f.tlvv = ProtoField.bytes("qmi.tlv_value", "TLV Value")

local awd_proto_prefix = "qmi.tlv.awd.0x1010.0x34."
local protbuf_dissector = Dissector.get("protobuf")
f.tlvv_awd_app = ProtoField.uint32(awd_proto_prefix .. "app", "App ID")
f.tlvv_awd_component = ProtoField.uint32(awd_proto_prefix .. "component", "Component ID")
f.tlvv_awd_trigger = ProtoField.uint32(awd_proto_prefix .. "trigger", "App ID")
f.tlvv_awd_profile = ProtoField.uint32(awd_proto_prefix .. "profile", "Profile ID")
f.tlvv_awd_metric = ProtoField.uint32(awd_proto_prefix .. "metric", "Metric ID")
f.tlvv_awd_submission = ProtoField.uint32(awd_proto_prefix .. "submission", "Submission ID")
f.tlvv_awd_other = ProtoField.uint16(awd_proto_prefix .. "other", "Other ID")
f.tlvv_awd_payload_length = ProtoField.uint16(awd_proto_prefix .. "payload_length", "Payload Length")
f.tlvv_awd_payload = ProtoField.bytes(awd_proto_prefix .. "payload", "Payload")

--
-- Utils Functions
--

compare_tvb = function(a1, a2, a_len)
	for i = 0, a_len - 1
	do
		if a1(i, 1):uint() ~= a2(i, 1):uint() then
			return false
		end
	end

	return true
end

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then
		val = "(unknown)"
	end
	return val
end

--
-- Dissector Function
--
function qmi_proto.dissector(buffer, pinfo, tree)
	-- Change this variable manually to build the dissector with support for direction information.
	-- Warning: This only works in combination with the command 'watch_frida.py --directionbit'
	local direction_bit = false

	-- Set offset according to operating system
	local off = 0
	if direction_bit then
		off = 1
	end

	if buffer:len() - off < 12 then
		-- No payload or too short (12 is a min size)
		return
	end

	-- QMUX Header (6 bytes), see GobiNet/QMI.h, should always start with 0x01
	local tf = buffer(off, 1)
	if tf:uint() ~= 1 then
		-- Not a QMI packet
		return
	end
	local len = buffer(off + 1, 2)    -- Length
	if len:le_uint() ~= buffer:len() - off - 1 then
		-- Length does not match
		return
	end
	-- We could also use this flag to determine the packet's direction.
	-- Nevertheless, we should translate its binary values.
	-- Furthermore, Its value seems to be always equal to the properties req -> 0x00 and ind & resp -> 0x80
	local flag = buffer(off + 3, 1)    -- Always 0x00 (out) or 0x80 (in)
	if flag:uint() ~= 0x00 and flag:uint() ~= 0x80 then
		-- Not a QMI packet
		return
	end
	local svcid = buffer(off + 4, 1)    -- Service ID
	local cid = buffer(off + 5, 1)    -- Client ID

	-- Setup protocol subtree
	local qmitree = tree:add(qmi_proto, buffer(off, buffer:len() - off), "Qualcomm MSM Interface")
	local hdrtree = qmitree:add(qmi_proto, buffer(off, 6), "QMUX Header")
	hdrtree:add(f.tf, tf)
	hdrtree:add_le(f.len, len)
	hdrtree:add(f.flag, flag)
	hdrtree:add(f.svcid, svcid)
	hdrtree:add(f.svcname, service_names[svcid:uint()] and service_names[svcid:uint()] or "unknown"):set_generated(true)
	hdrtree:add(f.cid, cid)
	off = off + 6

	-- Transaction Header (2 or 3 bytes), see GobiAPI/Core/QMIBuffers.h
	local responsebit
	local indicationbit
	if svcid:uint() == 0 then
		responsebit = buffer(off, 1):bitfield(7)
		indicationbit = buffer(off, 1):bitfield(6)
		local thdrtree = qmitree:add(qmi_proto, buffer(off, 2), "Transaction Header")
		tid = buffer(off + 1, 1)
		thdrtree:add(f.resp_ctl, buffer(off, 1))
		thdrtree:add(f.ind_ctl, buffer(off, 1))
		thdrtree:add(f.tid_ctl, tid)
		off = off + 2
	else
		responsebit = buffer(off, 1):bitfield(6)
		indicationbit = buffer(off, 1):bitfield(5)
		local thdrtree = qmitree:add(qmi_proto, buffer(off, 3), "Transaction Header")
		tid = buffer(off + 1, 2)
		thdrtree:add(f.comp_svc, buffer(off, 1))
		thdrtree:add(f.resp_svc, buffer(off, 1))
		thdrtree:add(f.ind_svc, buffer(off, 1))
		thdrtree:add_le(f.tid_svc, tid)
		off = off + 3
	end

	-- iPhone: Get direction of packet by inspecting whether it is a indication
	-- We want to use Address.string() for display, but is not implemented for Lua, so we're using Address.eth()
	-- https://gitlab.com/wireshark/wireshark/-/blob/master/epan/wslua/wslua_address.c#L137
	local appleA14Eth = 'A9:91:E0:0A:14:00'
	local basebandEth = 'BA:8E:BA:9D:00:00'
	if direction_bit then
		-- This is the exact approach.
		local direction = buffer(0,1)
		if direction:uint() == 0 then
			-- Packet originates from the baseband and is sent to the iPhone's application processor
			pinfo.src = Address.ether(basebandEth)
			pinfo.dst = Address.ether(appleA14Eth)
		elseif direction:uint() == 1 then
			-- Packet originates from the iPhone's application processor and is sent the the baseband
			pinfo.src = Address.ether(appleA14Eth)
			pinfo.dst = Address.ether(basebandEth)
		else
			-- Invalid direction bit
		end
	else
		-- This is a rough approximation but works for 99% of all cases.
		-- If accuracy is required, use the watch_frida.py script with the --directionbit flag and
		-- enable the direction_bit setting in this dissector above.
		if responsebit == 1 or indicationbit == 1 then
			-- Packet originates from the baseband and is sent to the iPhone's application processor
			pinfo.src = Address.ether(basebandEth)
			pinfo.dst = Address.ether(appleA14Eth)
		else
			-- Packet originates from the iPhone's application processor and is sent the the baseband
			pinfo.src = Address.ether(appleA14Eth)
			pinfo.dst = Address.ether(basebandEth)
		end
	end

	-- Message Header (4 bytes), see GobiAPI/Core/QMIBuffers.h
	local msgstr
	msgid = buffer(off, 2)
	msglen = buffer(off + 2, 2)
	local mhdrtree = qmitree:add(qmi_proto, buffer(off, 4), "Message Header")


	-- GENERATE(TLV_LINK)


	mhdrtree:add_le(f.msglen, msglen)
	off = off + 4

	-- TLVs, see GobiAPI/Core/QMIBuffers.h
	local msgend = off + msglen:le_uint()
	while off < msgend do
		local tlvt = buffer(off, 1)
		local tlvl = buffer(off + 1, 2)
		local tlvv = buffer(off + 3, tlvl:le_uint())
		local tlv_name_available = pcall(function()
			tlv_name = tlv_description[msgid:le_uint()][tlvt:uint()]
		end)
		if not tlv_name_available then
			tlv_name = "Unknown TLV"
		end
		if tlv_name == nil then
			tlv_name = "Unknown TLV"
		end
		local treesize = tlvl:le_uint() + 3
		local treename = string.format("TLV 0x%.2x %s", tlvt:uint(), tlv_name)
		local tlvtree = qmitree:add(qmi_proto, buffer(off, treesize), treename)
		tlvtree:add(f.tlvt, tlvt)
		tlvtree:add_le(f.tlvl, tlvl)
		tlvtree:add(f.tlvv, tlvv)
		off = off + treesize
	end

	-- Setup columns
	local svcstr = services[svcid:uint()] and
			services[svcid:uint()] or string.format("0x%x", svcid:uint())
	local typestr = indicationbit == 1 and
			"Indication" or responsebit == 1 and "Response" or "Request"
	msgstr = msgstr ~= nil and msgstr or string.format("0x%x", msgid:le_uint())
	pinfo.cols.protocol = "QMI"
	pinfo.cols.info = string.format("%s %s: %s", svcstr, typestr, msgstr)
end
