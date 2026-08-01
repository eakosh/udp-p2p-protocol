local p_custom_protocol = Proto("PKS", "PKS PROTOCOL")

local SYN_FLAG = 0x80
local ACK_FLAG = 0x40
local NACK_FLAG = 0x20
local KA_FLAG = 0x10
local FLAG_RST = 0x08
local FIN_FLAG = 0x04
local DATA_FLAG = 0x02
local SYNACK_FLAG = 0xC0
local ACKKA_FLAG = 0x50
local ACKFIN_FLAG = 0x44
local TEXT_FLAG = 0x00
local ACKRST_FLAG = 0x48

local f_flags = ProtoField.uint8("custom_protocol.flags", "Flags", base.HEX)
local f_seq = ProtoField.uint16("custom_protocol.seq", "Sequence Number", base.DEC)
local f_ack = ProtoField.uint16("custom_protocol.ack", "Acknowledgment Number", base.DEC)
local f_total_fragments = ProtoField.uint16("custom_protocol.total_fragments", "Total Fragments", base.DEC)
local f_window_size = ProtoField.uint8("custom_protocol.window_size", "Window Size", base.DEC)
local f_checksum = ProtoField.uint16("custom_protocol.checksum", "Checksum", base.HEX)
local f_data = ProtoField.bytes("custom_protocol.data", "Data")

p_custom_protocol.fields = { f_flags, f_seq, f_ack, f_total_fragments, f_window_size, f_checksum, f_data }

function p_custom_protocol.dissector(buffer, pinfo, tree)
    if buffer:len() < 10 then return end

    local flags = buffer(0, 1):uint()
    local seq_number = buffer(1, 2):uint()
    local ack_number = buffer(3, 2):uint()
    local total_fragments = buffer(5, 2):uint()
    local window_size = buffer(7, 1):uint()
    local checksum = buffer(8, 2):uint()
    local data_field = buffer(10):bytes()

    local subtree = tree:add(p_custom_protocol, buffer(), "Custom Protocol Data")
    subtree:add(f_flags, flags)
    subtree:add(f_seq, seq_number)
    subtree:add(f_ack, ack_number)
    subtree:add(f_total_fragments, total_fragments)
    subtree:add(f_window_size, window_size)
    subtree:add(f_checksum, checksum)

    pinfo.cols.protocol:set("PKS")

    if flags & DATA_FLAG ~= 0 then
        pinfo.cols.info:set("Data Packet")
        pinfo.cols.info:append(" (" .. data_field:len() .. " bites)")
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT 
        subtree:set_text("Custom Protocol: Data Message")
    elseif flags == TEXT_FLAG then
        pinfo.cols.info:set("TEXT Packet")
        pinfo.cols.info:append(" (" .. data_field:len() .. " bites)")
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT  
        subtree:set_text("Custom Protocol: Data Message")
    else
        if flags == SYN_FLAG then
            pinfo.cols.info:set("SYN")
        elseif flags == ACK_FLAG then
            pinfo.cols.info:set("ACK")
        elseif flags == NACK_FLAG then
            pinfo.cols.info:set("NACK")
        elseif flags == KA_FLAG then
            pinfo.cols.info:set("Keep-Alive")
        elseif flags == FLAG_RST then
            pinfo.cols.info:set("RST")
        elseif flags == FIN_FLAG then
            pinfo.cols.info:set("FIN")
        elseif flags == SYNACK_FLAG then
            pinfo.cols.info:set("SYN-ACK")
        elseif flags == ACKKA_FLAG then
            pinfo.cols.info:set("ACK Keep-Alive")
        elseif flags == ACKFIN_FLAG then
            pinfo.cols.info:set("ACK-FIN")
        end

        subtree:set_text("Custom Protocol: Control Message")
    end
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(1111, p_custom_protocol)
udp_table:add(2222, p_custom_protocol)
