#
# Copyright (c) 2004 David R. Halliday
# All rights reserved.
#
# This SNMP library is free software.  Redistribution is permitted under the
# same terms and conditions as the standard Ruby distribution.  See the
# COPYING file in the Ruby distribution for details.
#

require 'snmp/ber'

include SNMP::BER

module SNMP

class UnsupportedValueTag < RuntimeError; end
class InvalidIpAddress < ArgumentError; end

class VarBindList < Array
    def self.decode(data)
        list = VarBindList.new
        varbind_data, remainder = decode_sequence(data)
        while varbind_data != ""
            varbind, varbind_data = VarBind.decode(varbind_data)
            list << varbind
        end
        return list, remainder    
    end

    def initialize(varbind_list=[])
        super()
        if varbind_list.respond_to? :to_str
            self << ObjectId.new(varbind_list.to_str).to_varbind
        elsif varbind_list.respond_to? :to_varbind
            self << varbind_list.to_varbind
        else
            varbind_list.each do |item|
                if item.respond_to? :to_str
                    self << ObjectId.new(item.to_str).to_varbind
                else
                    self << item.to_varbind
                end
            end
        end
    end
    
    def asn1_type
        "VarBindList"
    end
    
    def encode
        varbind_data = ""
        self.each do |varbind|
            varbind_data << varbind.encode
        end
        encode_sequence(varbind_data)
    end
end

class Integer
    include Comparable
    
    def self.decode(value_data)
        Integer.new(decode_integer_value(value_data))
    end
    
    def asn1_type
        "INTEGER"
    end

    def initialize(value)
        @value = value.to_i
    end

    def <=>(other)
        @value <=> other.to_i
    end
    
    def coerce(other)
        if other.kind_of? Integer
            return [other, @value]
        else
            return [other.to_f, self.to_f]
        end
    end
    
    def to_s
        @value.to_s
    end

    def to_i
        @value
    end
    
    def to_f
        @value.to_f
    end
    
    def encode
        encode_integer(@value)
    end
    
    def to_oid
        raise RangeError, "@{value} cannot be an OID (must be >0)" if @value < 0
        ObjectId.new([@value])
    end
end

class Integer32 < Integer
    def initialize(value)
        super(value)
        raise ArgumentError, "Out of range: #{value}" if value < -2147483648
        raise ArgumentError, "Out of range: #{value}" if value > 2147483647
    end
end

class OctetString < String
    def self.decode(value_data)
        OctetString.new(value_data)
    end

    def asn1_type
        "OCTET STRING"
    end
    
    def encode
        encode_octet_string(self)
    end
    
    def to_oid
        oid = ObjectId.new
        each_byte { |b| oid << b }
        oid
    end
end

class ObjectId < Array
    include Comparable
    
    def self.decode(value_data)
        ObjectId.new(decode_object_id_value(value_data))
    end

    def asn1_type
        "OBJECT IDENTIFIER"
    end
    
    ##
    # Create an object id.  The input is expected to be either a string
    # in the format "n.n.n.n.n.n" or an array of integers.
    #
    def initialize(id=[])
        if id.nil?
            raise ArgumentError
        elsif id.respond_to? :to_str
            super(make_integers(id.to_str.split(".")))
        else
            super(make_integers(id.to_ary))
        end
    rescue ArgumentError
        raise ArgumentError, "#{id.inspect}:#{id.class} not a valid object ID"
    end
    
    def to_varbind
        VarBind.new(self, Null)
    end
    
    def to_oid
        self
    end
    
    def to_s
        self.join('.')
    end
    
    def inspect
        "[#{self.to_s}]"
    end
    
    def encode
        encode_object_id(self)
    end
    
    ##
    # Returns true if this ObjectId is a subtree of the provided parent tree
    # ObjectId.  For example, "1.3.6.1.5" is a subtree of "1.3.6.1".
    #
    def subtree_of?(parent_tree)
        parent_tree = make_object_id(parent_tree)
        if parent_tree.length > self.length
            false
        else
            parent_tree.each_index do |i|
                return false if parent_tree[i] != self[i]
            end
            true
        end
    end
    
    ##
    # Returns an index based on the difference between this ObjectId
    # and the provided parent ObjectId.
    #
    # For example, ObjectId.new("1.3.6.1.5").index("1.3.6.1") returns an
    # ObjectId of "5".
    #
    def index(parent_tree)
        parent_tree = make_object_id(parent_tree)
        if not subtree_of?(parent_tree)
            raise ArgumentError, "#{self.to_s} not a subtree of #{parent_tree.to_s}"
        elsif self.length == parent_tree.length
            raise ArgumentError, "OIDs are the same"
        else
            ObjectId.new(self[parent_tree.length..-1])
        end
    end
    
    private
    
    def make_integers(list)
        list.collect{|n| Integer(n)}
    end 
    
    def make_object_id(oid)
        oid.kind_of?(ObjectId) ? oid : ObjectId.new(oid)
    end
    
end

class IpAddress
    class << self
        def decode(value_data)
            IpAddress.new(value_data)
        end
    end

    def asn1_type
        "IpAddress"
    end

    ##
    # Create an IpAddress object.  The constructor accepts either a raw
    # four-octet string or a formatted string of integers separated by dots
    # (i.e. "10.1.2.3").
    #
    def initialize(value_data)
        ip = value_data.to_str
        if ip.length > 4
            ip = parse_string(ip)
        elsif ip.length != 4
            raise InvalidIpAddress, "Expected 4 octets or formatted string, got #{value_data.inspect}"
        end
        @value = ip
    end
    
    ##
    # Returns a raw four-octet string representing this IpAddress.
    #
    def to_str
        @value.dup
    end
    
    ##
    # Returns a formatted, dot-separated string representing this IpAddress.
    #
    def to_s
        octets = []
        @value.each_byte { |b| octets << b.to_s }
        octets.join('.')    
    end
    
    def to_oid
        oid = ObjectId.new
        @value.each_byte { |b| oid << b }
        oid
    end
    
    def ==(other)
        if other.respond_to? :to_str
            return @value.eql?(other.to_str)
        else
            return false
        end
    end
    
    def eql?(other)
        self == other
    end
    
    def hash
        @value.hash
    end
    
    def encode
        encode_tlv(IpAddress_TAG, @value)
    end

    private
    def parse_string(ip_string)
        parts = ip_string.split(".")
        raise InvalidIpAddress, ip_string.inspect if parts.length != 4
        value_data = ""
        parts.each do |s| 
            octet = s.to_i
            raise InvalidIpAddress, ip_string.inspect if octet > 255
            raise InvalidIpAddress, ip_string.inspect if octet < 0
            value_data << octet.chr
        end
        value_data
    end

end

class UnsignedInteger < Integer
    def initialize(value)
        super(value)
        raise ArgumentError, "Negative integer invalid: #{value}" if value < 0
        raise ArgumentError, "Out of range: #{value}" if value > 4294967295
    end
    
    def self.decode(value_data)
        self.new(decode_uinteger_value(value_data))
    end
end

class Counter32 < UnsignedInteger
    def asn1_type
        "Counter32"
    end

    def encode
        encode_tagged_integer(Counter32_TAG, @value)
    end
end

class Gauge32 < UnsignedInteger
    def asn1_type
        "Gauge32"
    end

    def encode
        encode_tagged_integer(Gauge32_TAG, @value)
    end
end

class Unsigned32 < UnsignedInteger
    def asn1_type
        "Unsigned32"
    end

    def encode
        encode_tagged_integer(Unsigned32_TAG, @value)
    end
end

class TimeTicks < UnsignedInteger
    def asn1_type
        "TimeTicks"
    end

    def encode
        encode_tagged_integer(TimeTicks_TAG, @value)
    end
    
    def to_s
        days, remainder = @value.divmod(8640000)
        hours, remainder = remainder.divmod(360000)
        minutes, remainder = remainder.divmod(6000)
        seconds, hundredths = remainder.divmod(100)
        case
            when days < 1
                sprintf('%02d:%02d:%02d.%02d',
                        hours, minutes, seconds, hundredths)
            when days == 1
                sprintf('1 day, %02d:%02d:%02d.%02d',
                        hours, minutes, seconds, hundredths)
            when days > 1
                sprintf('%d days, %02d:%02d:%02d.%02d',
                        days, hours, minutes, seconds, hundredths)
        end
    end
end

class Opaque < OctetString
    def self.decode(value_data)
        Opaque.new(value_data)
    end
    
    def asn1_type
        "Opaque"
    end
    
    def encode
        encode_tlv(Opaque_TAG, self)
    end
end

class Counter64 < Integer
    def self.decode(value_data)
        Counter64.new(decode_integer_value(value_data))
    end

    def asn1_type
        "Counter64"
    end

    def initialize(value)
        super(value)
        raise ArgumentError, "Negative integer invalid: #{value}" if value < 0
        raise ArgumentError, "Out of range: #{value}" if value > 18446744073709551615
    end    
    
    def encode
        encode_tagged_integer(Counter64_TAG, @value)
    end
end

class Null
    class << self
        def decode(value_data)
            Null
        end

        def encode
            encode_null
        end
        
        def asn1_type
            'Null'
        end

        def to_s
            asn1_type
        end
    end
end

class NoSuchObject
    class << self
        def decode(value_data)
            NoSuchObject
        end

        def encode
            encode_exception(NoSuchObject_TAG)
        end

        def asn1_type
            'noSuchObject'
        end
        
        def to_s
            asn1_type
        end
    end
end

class NoSuchInstance
    class << self
        def decode(value_data)
            NoSuchInstance
        end

        def encode
            encode_exception(NoSuchInstance_TAG)
        end
        
        def asn1_type
            'noSuchInstance'
        end
        
        def to_s
            asn1_type
        end
    end
end

class EndOfMibView
    class << self
        def decode(value_data)
            EndOfMibView
        end

        def encode
            encode_exception(EndOfMibView_TAG)
        end
        
        def asn1_type
            'endOfMibView'
        end
        
        def to_s
            asn1_type
        end
    end
end

class VarBind
    attr_accessor :name
    attr_accessor :value
    
    alias :oid :name
    
    class << self
        def decode(data)
            varbind_data, remaining_varbind_data = decode_sequence(data)
            name, remainder = decode_object_id(varbind_data)
            value, remainder = decode_value(remainder)
            assert_no_remainder(remainder)
            return VarBind.new(name, value), remaining_varbind_data
        end

        ValueDecoderMap = {
            INTEGER_TAG           => Integer,
            OCTET_STRING_TAG      => OctetString,
            NULL_TAG              => Null,
            OBJECT_IDENTIFIER_TAG => ObjectId,
            IpAddress_TAG         => IpAddress,
            Counter32_TAG         => Counter32,
            Gauge32_TAG           => Gauge32,
            # note Gauge32 tag same as Unsigned32
            TimeTicks_TAG         => TimeTicks,
            Opaque_TAG            => Opaque,
            Counter64_TAG         => Counter64,
            NoSuchObject_TAG      => NoSuchObject,
            NoSuchInstance_TAG    => NoSuchInstance,
            EndOfMibView_TAG      => EndOfMibView
        }
        
        def decode_value(data)
            value_tag, value_data, remainder = decode_tlv(data)
            decoder_class = ValueDecoderMap[value_tag]
            if decoder_class
                value = decoder_class.decode(value_data)
            else
               raise UnsupportedValueTag, value_tag.to_s
            end
            return value, remainder
        end
    end
    
    def initialize(name, value=Null)
        if name.kind_of? ObjectId
            @name = name
        else
            @name = ObjectName.new(name)
        end
        @value = value
    end

    def asn1_type
        "VarBind"
    end
    
    def to_varbind
        self
    end
    
    def to_s
        "[name=#{@name.to_s}, value=#{@value.to_s} (#{@value.asn1_type})]"
    end
    
    def each
        yield self
    end
    
    def encode
        data = encode_object_id(@name) << value.encode
        encode_sequence(data)
    end
end

class ObjectName < ObjectId
    def asn1_type
        "ObjectName"
    end
end

end
