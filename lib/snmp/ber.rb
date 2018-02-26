#
# Copyright (c) 2004 David R. Halliday
# All rights reserved.
#
# This SNMP library is free software.  Redistribution is permitted under the
# same terms and conditions as the standard Ruby distribution.  See the
# COPYING file in the Ruby distribution for details.
#

#
# Add ord method to Integer for forward compatibility with Ruby 1.9
#
if "a"[0].kind_of? Integer
    unless Integer.methods.include? :ord
        class Integer
            def ord; self; end
        end
    end
end

#
# This module implements methods for encoding and decoding SNMP packets
# using the ASN.1 BER (Basic Encoding Rules).
#
module SNMP
module BER #:nodoc:all

    # SNMP version codes
    SNMP_V1  = 0
    SNMP_V2C = 1
    SNMP_V3  = 3  # not supported

    # SNMP context-specific data types
    # See RFC 1157 for SNMPv1
    # See RFC 1905 for SNMPv2c
    GetRequest_PDU_TAG = 0xa0
    GetNextRequest_PDU_TAG = 0xa1
    Response_PDU_TAG = 0xa2
    SetRequest_PDU_TAG = 0xa3
    SNMPv1_Trap_PDU_TAG = 0xa4    # Note: valid for SNMPv1 only
    GetBulkRequest_PDU_TAG = 0xa5
    InformRequest_PDU_TAG = 0xa6
    SNMPv2_Trap_PDU_TAG = 0xa7
    Report_PDU_TAG = 0xa8  # Note: Usage not defined - not supported    

    # Primitive ASN.1 data types
    INTEGER_TAG = 0x02
    OCTET_STRING_TAG = 0x04
    NULL_TAG = 0x05
    OBJECT_IDENTIFIER_TAG = 0x06
    
    # Constructed ASN.1 data type
    SEQUENCE_TAG = 0x30
    
    # SNMP application data types
    # See RFC 1155 for SNMPv1
    # See RFC 1902 for SNMPv2c
    IpAddress_TAG = 0x40
    Counter32_TAG = 0x41   # Counter in SNMPv1
    Gauge32_TAG = 0x42     # Gauge in SNMPv1
    Unsigned32_TAG = 0x42  # Note: same as Gauge32
    TimeTicks_TAG = 0x43
    Opaque_TAG = 0x44
    Counter64_TAG = 0x46
    
    # VarBind response exceptions
    NoSuchObject_TAG = 0x80
    NoSuchInstance_TAG = 0x81
    EndOfMibView_TAG = 0x82
    
    # Exceptions thrown in this module
    class OutOfData < RuntimeError; end    
    class InvalidLength < RuntimeError; end
    class InvalidTag < RuntimeError; end
    class InvalidObjectId < RuntimeError; end

    def assert_no_remainder(remainder)
        raise ParseError, remainder.inspect if (remainder and remainder != "")
    end
    
    #
    # Decode tag-length-value data.  The data is assumed to be a string of
    # bytes in network byte order.  This format is returned by Socket#recv.
    #
    # Returns a tuple containing the tag, the value, and any remaining
    # unprocessed data.
    #
    # The data is not interpretted by this method.  Use one of the other
    # decoding methods to interpret the data.
    #
    # Note that ASN.1 supports an indefinite length format where the end of
    # content is marked by a pair of 0 octets.  SNMP does not support this
    # format, so only the two definite forms are implemented (single byte and
    # multi-byte).
    #
    def decode_tlv(data)
        raise OutOfData if (data.length == 2 && data[1].ord != 0) || data.length < 2
        tag = data[0].ord
        length = data[1].ord
        if length < 0x80
            value = data[2, length]
            remainder = data[length+2..-1]
        else
            # ASN.1 says this octet can't be 0xff
            raise InvalidLength, length.to_s if length == 0xff
            num_octets = length & 0x7f
            length = build_integer(data, 2, num_octets)
            value = data[num_octets+2, length]
            remainder = data[num_octets+2+length..-1]
        end
        return tag, value, remainder
    end
    
    #
    # Decode TLV data for an ASN.1 integer.
    #
    # Throws an InvalidTag exception if the tag is incorrect.
    #
    # Returns a tuple containing an integer and any remaining unprocessed data.
    #
    def decode_integer(data)
        tag, value, remainder = decode_tlv(data)
        raise InvalidTag, tag.to_s if tag != INTEGER_TAG
        return decode_integer_value(value), remainder
    end

    def decode_timeticks(data)
        tag, value, remainder = decode_tlv(data)
        raise InvalidTag, tag.to_s if tag != TimeTicks_TAG
        return decode_uinteger_value(value), remainder
    end
    
    def decode_integer_value(value)
        result = build_integer(value, 0, value.length)
        if value[0].ord[7] == 1
            result -= (1 << (8 * value.length))
        end
        result
    end
    
    ##
    # Decode an integer, ignoring the sign bit.  Some agents insist on
    # encoding 32 bit unsigned integers with four bytes even though it
    # should be 5 bytes (at least the way I read it).
    #
    def decode_uinteger_value(value)
        build_integer(value, 0, value.length)
    end
    
    def build_integer(data, start, num_octets)
        number = 0
        num_octets.times { |i| number = number<<8 | data[start+i].ord }
        return number
    end

    #
    # Decode TLV data for an ASN.1 octet string.
    #
    # Throws an InvalidTag exception if the tag is incorrect.
    #
    # Returns a tuple containing a string and any remaining unprocessed data.
    #    
    def decode_octet_string(data)
        tag, value, remainder = decode_tlv(data)
        raise InvalidTag, tag.to_s if tag != OCTET_STRING_TAG
        return value, remainder
    end
    
    def decode_ip_address(data)
        tag, value, remainder = decode_tlv(data)
        raise InvalidTag, tag.to_s if tag != IpAddress_TAG
        raise InvalidLength, tag.to_s if value.length != 4
        return value, remainder
    end
    
    #
    # Decode TLV data for an ASN.1 sequence.
    #
    # Throws an InvalidTag exception if the tag is incorrect.
    #
    # Returns a tuple containing the sequence data and any remaining 
    # unprocessed data that follows the sequence.
    #
    def decode_sequence(data)
        tag, value, remainder = decode_tlv(data)
        raise InvalidTag, tag.to_s if tag != SEQUENCE_TAG
        return value, remainder
    end
    
    #
    # Unwrap TLV data for an ASN.1 object identifier.  This method extracts
    # the OID value as a character string but does not decode it further.
    #
    # Throws an InvalidTag exception if the tag is incorrect.
    #
    # Returns a tuple containing the object identifier (OID) and any
    # remaining unprocessed data.  The OID is represented as an array
    # of integers.
    #
    def decode_object_id(data)
        tag, value, remainder = decode_tlv(data)
        raise InvalidTag, tag.to_s if tag != OBJECT_IDENTIFIER_TAG
        return decode_object_id_value(value), remainder
    end
    
    def decode_object_id_value(value)
        if value.length == 0
            object_id = []
        else
            value0 = value[0].ord
            if value0 == 0x2b
                object_id = [1,3]
            else
                second = value0 % 40
                first = (value0 - second) / 40
                raise InvalidObjectId, value.to_s if first > 2
                object_id = [first, second]
            end
            n = 0
            for i in 1...value.length
                n = (n<<7) + (value[i].ord & 0x7f)
                if value[i].ord < 0x80
                    object_id << n
                    n = 0
                end 
            end
        end
        return object_id
    end
    
    #
    # Encode the length field for TLV data.  Returns the length octets
    # as a string.
    #
    def encode_length(length)
        raise InvalidLength, length.to_s if length < 0
        if length < 0x80
            length.chr
        else
            data = integer_to_octets(length)
            (data.size | 0x80).chr << data
        end
    end

    #
    # Encode integer
    #
    def encode_integer(value)
        encode_tagged_integer(INTEGER_TAG, value)
    end
    
    def encode_tagged_integer(tag, value)
        if value > 0 && value < 0x80
            data = value.chr
        else
            data = integer_to_octets(value)
            if value > 0 && data[0].ord > 0x7f
                data = "\000" << data 
            elsif value < 0 && data[0].ord < 0x80
                data = "\377" << data
            end
        end
        encode_tlv(tag, data)
    end
    
    #
    # Helper method for encoding integer-like things.
    #
    def integer_to_octets(i)
        if i >= 0
            done = 0
        else
            done = -1
        end
        octets = ""
        begin
            octets = (i & 0xff).chr << octets
            i = i >> 8
        end until i == done
        octets
    end
    
    def encode_null
        NULL_TAG.chr << "\000"
    end
    
    #
    # Encode an exception.  The encoding is simply the exception tag with
    # no data, similar to NULL.
    #
    def encode_exception(tag)
        tag.chr << "\000"
    end
    
    #
    # Wraps value in a tag and length.  This method expects an
    # integer tag and a string value.
    #
    def encode_tlv(tag, value)
        data = tag.chr << encode_length(value.length)
        data = data << value if value.length > 0
        data
    end
    
    #
    # Wrap string in a octet string tag and length.
    #
    def encode_octet_string(value)
        encode_tlv(OCTET_STRING_TAG, value)
    end
    
    #
    # Wrap value in a sequence tag and length.
    #
    def encode_sequence(value)
        encode_tlv(SEQUENCE_TAG, value)
    end
    
    #
    # Encode an object id.  The input is assumed to be an array of integers
    # representing the object id.
    #
    def encode_object_id(value)
        raise InvalidObjectId, value.to_s if value.length < 1
        raise InvalidObjectId, value.to_s if value[0] > 2
        data = ""
        if (value.length > 1)
            raise InvalidObjectId if value[0] < 2 && value[1] > 40
            data << (40 * value[0] + value[1]).chr
            for i in 2...value.length
                if value[i] < 0x80
                    data << value[i].chr
                else
                    octets = ""
                    n = value[i]
                    begin
                        octets = (n & 0x7f | 0x80).chr << octets
                        n = n >> 7
                    end until n == 0
                    octets[-1] = (octets[-1].ord & 0x7f).chr
                    data << octets
                end
            end
        elsif (value.length == 1)
            data << (40 * value[0]).chr
        end
        encode_tlv(OBJECT_IDENTIFIER_TAG, data)
    end
    
end
end

