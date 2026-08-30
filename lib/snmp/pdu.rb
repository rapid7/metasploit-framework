#
# Copyright (c) 2004 David R. Halliday
# All rights reserved.
#
# This SNMP library is free software.  Redistribution is permitted under the
# same terms and conditions as the standard Ruby distribution.  See the
# COPYING file in the Ruby distribution for details.
#

require 'snmp/ber'
require 'snmp/varbind'

include SNMP::BER

module SNMP

# Exceptions thrown during message/pdu decoding
class UnsupportedVersion < RuntimeError; end
class UnsupportedPduTag < RuntimeError; end
class InvalidPduTag < RuntimeError; end
class ParseError < RuntimeError; end
class InvalidErrorStatus < RuntimeError; end
class InvalidTrapVarbind < RuntimeError; end
class InvalidGenericTrap < RuntimeError; end

SYS_UP_TIME_OID = ObjectId.new("1.3.6.1.2.1.1.3.0")
SNMP_TRAP_OID_OID = ObjectId.new("1.3.6.1.6.3.1.1.4.1.0")

class Message
    attr_reader :version
    attr_reader :community
    attr_reader :pdu
    
    class << self
        def decode(data)
            message_data, remainder = decode_sequence(data)
            assert_no_remainder(remainder)
            version, remainder = decode_version(message_data)
            community, remainder = decode_octet_string(remainder)
            pdu, remainder = decode_pdu(version, remainder)
            assert_no_remainder(remainder)
            Message.new(version, community, pdu)
        end

        def decode_version(data)
            version_data, remainder = decode_integer(data)
            if version_data == SNMP_V1
                version = :SNMPv1
            elsif version_data == SNMP_V2C
                version = :SNMPv2c
            else
                raise UnsupportedVersion, version_data.to_s
            end
            return version, remainder
        end
        
        def decode_pdu(version, data)
            pdu_tag, pdu_data, remainder = decode_tlv(data)
            case pdu_tag
            when GetRequest_PDU_TAG
                pdu = PDU.decode(GetRequest, pdu_data)
            when GetNextRequest_PDU_TAG
                pdu = PDU.decode(GetNextRequest, pdu_data)
            when Response_PDU_TAG
                pdu = PDU.decode(Response, pdu_data)
            when SetRequest_PDU_TAG
                pdu = PDU.decode(SetRequest, pdu_data)
            when SNMPv1_Trap_PDU_TAG
                raise InvalidPduTag, "SNMPv1-trap not valid for #{version.to_s}" if version != :SNMPv1
                pdu = SNMPv1_Trap.decode(pdu_data)
            when GetBulkRequest_PDU_TAG
                raise InvalidPduTag, "get-bulk not valid for #{version.to_s}" if version != :SNMPv2c
                pdu = PDU.decode(GetBulkRequest, pdu_data)
            when InformRequest_PDU_TAG
                raise InvalidPduTag, "inform not valid for #{version.to_s}" if version != :SNMPv2c
                pdu = PDU.decode(InformRequest, pdu_data)
            when SNMPv2_Trap_PDU_TAG
                raise InvalidPduTag, "SNMPv2c-trap not valid for #{version.to_s}" if version != :SNMPv2c
                pdu = PDU.decode(SNMPv2_Trap, pdu_data)
            else
                raise UnsupportedPduTag, pdu_tag.to_s
            end
            return pdu, remainder
        end
    end
    
    def initialize(version, community, pdu)
        @version = version
        @community = community
        @pdu = pdu
    end
    
    def response
        Message.new(@version, @community, Response.from_pdu(@pdu))
    end
    
    def encode_version(version)
        if version == :SNMPv1
            encode_integer(SNMP_V1)
        elsif version == :SNMPv2c
            encode_integer(SNMP_V2C)
        else
            raise UnsupportedVersion, version.to_s
        end
    end
    
    def encode
        data = encode_version(@version)
        data << encode_octet_string(@community)
        data << @pdu.encode
        encode_sequence(data)
    end
end

class PDU
    attr_accessor :request_id
    attr_accessor :error_index
    attr_accessor :varbind_list
    
    alias vb_list varbind_list
    
    def self.decode(pdu_class, pdu_data)
        request_id, remainder = decode_integer(pdu_data)
        error_status, remainder = decode_integer(remainder)
        error_index, remainder = decode_integer(remainder)
        varbind_list, remainder = VarBindList.decode(remainder)
        assert_no_remainder(remainder)
        pdu_class.new(request_id, varbind_list, error_status, error_index)
    end

    ERROR_STATUS_NAME = {
         0 => :noError,
         1 => :tooBig,
         2 => :noSuchName,
         3 => :badValue,
         4 => :readOnly,
         5 => :genErr,
         6 => :noAccess,
         7 => :wrongType,
         8 => :wrongLength,
         9 => :wrongEncoding,
        10 => :wrongValue,
        11 => :noCreation,
        12 => :inconsistentValue,
        13 => :resourceUnavailable,
        14 => :commitFailed,
        15 => :undoFailed,
        16 => :authorizationError,
        17 => :notWritable,
        18 => :inconsistentName
    }
    
    ERROR_STATUS_CODE = ERROR_STATUS_NAME.invert
    
    def initialize(request_id, varbind_list, error_status=0, error_index=0)
        @request_id = request_id
        self.error_status = error_status
        @error_index = error_index.to_int
        @varbind_list = varbind_list
    end
    
    def error_status=(status)
        @error_status = ERROR_STATUS_CODE[status]
        unless @error_status
            if status.respond_to?(:to_int) && ERROR_STATUS_NAME[status.to_int]
                @error_status = status
            else
                raise InvalidErrorStatus, status.to_s
            end
        end
    end
    
    def error_status
        ERROR_STATUS_NAME[@error_status]
    end
    
    def encode_pdu(pdu_tag)
        pdu_data = encode_integer(@request_id)
        pdu_data << encode_integer(@error_status)
        pdu_data << encode_integer(@error_index)
        pdu_data << @varbind_list.encode
        encode_tlv(pdu_tag, pdu_data)
    end
    
    def each_varbind(&block)
        @varbind_list.each(&block)
    end
end

class GetRequest < PDU
    def encode
        encode_pdu(GetRequest_PDU_TAG)
    end
end

class GetNextRequest < PDU
    def encode
        encode_pdu(GetNextRequest_PDU_TAG)
    end
end

class SetRequest < PDU
    def encode
        encode_pdu(SetRequest_PDU_TAG)
    end
end

class GetBulkRequest <  PDU
    alias max_repetitions error_index
    alias max_repetitions= error_index=
    
    def encode
        encode_pdu(GetBulkRequest_PDU_TAG)
    end
    
    def non_repeaters=(number)
        @error_status = number
    end
    
    def non_repeaters
        @error_status
    end
end

class Response < PDU
    class << self
        def from_pdu(request)
            Response.new(request.request_id, request.varbind_list,
                :noError, 0)
        end
    end
    
    def encode
        encode_pdu(Response_PDU_TAG)
    end
end

##
# The PDU class for traps in SNMPv2c.  Methods are provided for retrieving
# the values of the mandatory varbinds: the system uptime and the OID of the
# trap.  The complete varbind list is available through the usual varbind_list
# method.  The first two varbinds in this list will always be the uptime
# and trap OID varbinds.
#
class SNMPv2_Trap < PDU
    def encode
        encode_pdu(SNMPv2_Trap_PDU_TAG)
    end

    ##
    # Returns the source IP address for the trap, usually derived from the
    # source IP address of the packet that delivered the trap.
    # 
    attr_accessor :source_ip
    
    ##
    # Returns the value of the mandatory sysUpTime varbind for this trap.
    #
    # Throws InvalidTrapVarbind if the sysUpTime varbind is not present.
    #
    def sys_up_time
        varbind = @varbind_list[0]
        if varbind && (varbind.name == SYS_UP_TIME_OID)
            return varbind.value
        else
            raise InvalidTrapVarbind, "Expected sysUpTime.0, found " + varbind.to_s
        end
    end

    ##
    # Returns the value of the mandatory snmpTrapOID varbind for this trap.
    #
    # Throws InvalidTrapVarbind if the snmpTrapOID varbind is not present.
    #
    def trap_oid
        varbind = @varbind_list[1]
        if varbind && (varbind.name == SNMP_TRAP_OID_OID)
            return varbind.value
        else
            raise InvalidTrapVarbind, "Expected snmpTrapOID.0, found " + varbind.to_s 
        end
    end
end

##
# The PDU class for SNMPv2 Inform notifications.  This class is identical
# to SNMPv2_Trap.
#
class InformRequest < SNMPv2_Trap
    def encode
        encode_pdu(InformRequest_PDU_TAG)
    end
end

##
# The PDU class for traps in SNMPv1.
#
class SNMPv1_Trap
    ##
    # Returns the source IP address for the trap, usually derived from the
    # source IP address of the packet that delivered the trap.
    # 
    attr_accessor :source_ip

    attr_accessor :enterprise
    attr_accessor :agent_addr
    attr_accessor :specific_trap
    attr_accessor :timestamp
    attr_accessor :varbind_list
    
    alias :vb_list :varbind_list
    
    def self.decode(pdu_data)
        oid_data, remainder = decode_object_id(pdu_data)
        enterprise = ObjectId.new(oid_data)
        ip_data, remainder = decode_ip_address(remainder)
        agent_addr = IpAddress.new(ip_data)
        generic_trap, remainder = decode_integer(remainder)
        specific_trap, remainder = decode_integer(remainder)
        time_data, remainder = decode_timeticks(remainder)
        timestamp = TimeTicks.new(time_data)
        varbind_list, remainder = VarBindList.decode(remainder)
        assert_no_remainder(remainder)
        SNMPv1_Trap.new(enterprise, agent_addr, generic_trap, specific_trap,
            timestamp, varbind_list)
    end

    def initialize(enterprise, agent_addr, generic_trap, specific_trap, timestamp, varbind_list)
        @enterprise = enterprise
        @agent_addr = agent_addr
        self.generic_trap = generic_trap
        @specific_trap = specific_trap
        @timestamp = timestamp
        @varbind_list = varbind_list 
    end
    
    # Name map for all of the generic traps defined in RFC 1157.
    GENERIC_TRAP_NAME = {
        0 => :coldStart,
        1 => :warmStart,
        2 => :linkDown,
        3 => :linkUp,
        4 => :authenticationFailure,
        5 => :egpNeighborLoss,
        6 => :enterpriseSpecific
    }
    
    # Code map for all of the generic traps defined in RFC 1157.
    GENERIC_TRAP_CODE = GENERIC_TRAP_NAME.invert
    
    def generic_trap=(trap)
        @generic_trap = GENERIC_TRAP_CODE[trap]
        unless @generic_trap
            if trap.respond_to?(:to_i) && GENERIC_TRAP_NAME[trap.to_i]
                @generic_trap = trap
            else
                raise InvalidGenericTrap, trap.to_s
            end
        end
    end
    
    def generic_trap
        GENERIC_TRAP_NAME[@generic_trap]
    end
    
    def encode
        pdu_data = @enterprise.encode <<
                   @agent_addr.encode <<
                   encode_integer(@generic_trap) <<
                   encode_integer(@specific_trap) <<
                   @timestamp.encode <<
                   @varbind_list.encode
        encode_tlv(SNMPv1_Trap_PDU_TAG, pdu_data)
    end
    
    def each_varbind(&block)
        @varbind_list.each(&block)
    end
end

end
