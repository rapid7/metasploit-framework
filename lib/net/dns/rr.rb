#
#       $Id: RR.rb,v 1.19 2006/07/28 07:33:36 bluemonk Exp $    
#

require 'net/dns/names/names'
require 'net/dns/rr/types'
require 'net/dns/rr/classes'


%w[a ns mx cname txt soa ptr aaaa mr].each do |file|
  require "net/dns/rr/#{file}"
end

module Net # :nodoc:
  module DNS 
    
    # =Name
    #
    # Net::DNS::RR - DNS Resource Record class
    #
    # =Synopsis
    # 
    #   require 'net/dns/rr'
    #
    # =Description
    # 
    # The Net::DNS::RR is the base class for DNS Resource 
    # Record (RR) objects. A RR is a pack of data that represents
    # resources for a DNS zone. The form in which this data is 
    # shows can be drawed as follow:
    #
    #   "name  ttl  class  type  data"
    # 
    # The +name+ is the name of the resource, like an canonical
    # name for an +A+ record (internet ip address). The +ttl+ is the
    # time to live, expressed in seconds. +type+ and +class+ are 
    # respectively the type of resource (+A+ for ip addresses, +NS+
    # for nameservers, and so on) and the class, which is almost 
    # always +IN+, the Internet class. At the end, +data+ is the
    # value associated to the name for that particular type of 
    # resource record. An example:
    #
    #   # A record for IP address
    #   "www.example.com  86400  IN  A  172.16.100.1"
    #   
    #   # NS record for name server
    #   "www.example.com  86400  IN  NS  ns.example.com"
    #
    # A new RR object can be created in 2 ways: passing a string
    # such the ones above, or specifying each field as the pair
    # of an hash. See the Net::DNS::RR.new method for details.
    #
    # =Error classes
    #
    # Some error classes has been defined for the Net::DNS::RR class,
    # which are listed here to keep a light and browsable main documentation.
    # We have:
    #
    # * RRArgumentError: Generic argument error for class Net::DNS::RR
    # * RRDataError: Error in parsing binary data, maybe from a malformed packet
    #
    # =Copyright
    # 
    # Copyright (c) 2006 Marco Ceresa
    #
    # All rights reserved. This program is free software; you may redistribute 
    # it and/or modify it under the same terms as Ruby itself.
    #
    class RR
      include Net::DNS::Names
      
      # Regexp matching an RR string
      RR_REGEXP = Regexp.new("^\\s*(\\S+)\\s*(\\d+)?\\s+(" +
                               Net::DNS::RR::Classes.regexp + 
                               "|CLASS\\d+)?\\s*(" +
                               Net::DNS::RR::Types.regexp + 
                               "|TYPE\\d+)?\\s*(.*)$", Regexp::IGNORECASE)

      # Dimension of the sum of class, type, TTL and rdlength fields in a
      # RR portion of the packet, in bytes
      RRFIXEDSZ = 10

      # Name of the RR
      attr_reader :name
      # TTL time (in seconds) of the RR
      attr_reader :ttl
      # Data belonging to that appropriate class, 
      # not to be used (use real accessors instead)
      attr_reader :rdata
      
      # Create a new instance of Net::DNS::RR class, or an instance of
      # any of the subclass of the appropriate type.
      # 
      # Argument can be a string or an hash. With a sting, we can pass
      # a RR resource record in the canonical format:
      #
      #   a     = Net::DNS::RR.new("foo.example.com. 86400 A 10.1.2.3")
      #   mx    = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #   cname = Net::DNS::RR.new("www.example.com 300 IN CNAME www1.example.com")
      #   txt   = Net::DNS::RR.new('baz.example.com 3600 HS TXT "text record"')
      #
      # Incidentally, +a+, +mx+, +cname+ and +txt+ objects will be instances of
      # respectively Net::DNS::RR::A, Net::DNS::RR::MX, Net::DNS::RR::CNAME and 
      # Net::DNS::RR::TXT classes.
      #
      # The name and RR data are required; all other informations are optional.  
      # If omitted, the +TTL+ defaults to 10800, +type+ default to +A+ and the RR class
      # defaults to +IN+.  Omitting the optional fields is useful for creating the 
      # empty RDATA sections required for certain dynamic update operations.
      # All names must be fully qualified.  The trailing dot (.) is optional.
      #
      # The preferred method is however passing an hash with keys and values:
      #
      #   rr = Net::DNS::RR.new(
      #                 :name    => "foo.example.com",
      #                 :ttl     => 86400,
      #                 :cls     => "IN",
      #                 :type    => "A",
      #                 :address => "10.1.2.3"
      #         )
      #
      #   rr = Net::DNS::RR.new(
      #                 :name => "foo.example.com",
      #                 :rdata => "10.1.2.3"
      #         )
      #
      # Name and data are required; all the others fields are optionals like 
      # we've seen before. The data field can be specified either with the 
      # right name of the resource (+:address+ in the example above) or with
      # the generic key +:rdata+. Consult documentation to find the exact name
      # for the resource in each subclass.
      # 
      def initialize(arg)
        case arg
        when String
          instance = new_from_string(arg)
        when Hash
          instance = new_from_hash(arg)
        else
          raise RRArgumentError, "Invalid argument, must be a RR string or an hash of values"
        end

        if @type.to_s == "ANY"
          @cls = Net::DNS::RR::Classes.new("IN")
        end

        build_pack
        set_type

        instance
      end

      # Return a new RR object of the correct type (like Net::DNS::RR::A
      # if the type is A) from a binary string, usually obtained from
      # network stream.
      #
      # This method is used when parsing a binary packet by the Packet
      # class.
      # 
      def RR.parse(data)
        o = allocate
        obj,offset = o.send(:new_from_binary, data, 0)
        return obj
      end
      
      # Same as RR.parse, but takes an entire packet binary data to 
      # perform name expansion. Default when analizing a packet
      # just received from a network stream.
      #
      # Return an instance of appropriate class and the offset 
      # pointing at the end of the data parsed.
      #
      def RR.parse_packet(data,offset)
        o = allocate
        o.send(:new_from_binary,data,offset)
      end

      # Return the RR object in binary data format, suitable 
      # for using in network streams, with names compressed. 
      # Must pass as arguments the offset inside the packet
      # and an hash of compressed names.
      #
      # This method is to be used in other classes and is 
      # not intended for user space programs.
      #
      # TO FIX in one of the future releases
      #
      def comp_data(offset,compnames)
        type,cls = @type.to_i, @cls.to_i
        str,offset,names = dn_comp(@name,offset,compnames)
        str += [type,cls,@ttl,@rdlength].pack("n2 N n")
        offset += Net::DNS::RRFIXEDSZ
        return str,offset,names
      end
      
      # Return the RR object in binary data format, suitable 
      # for using in network streams.
      #
      #   raw_data = rr.data
      #   puts "RR is #{raw_data.size} bytes long"
      #
      def data
        type,cls = @type.to_i, @cls.to_i
        str = pack_name(@name)
        return str + [type,cls,@ttl,@rdlength].pack("n2 N n") + get_data
      end
      
      # Canonical inspect method    
      #
      #   mx = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #     #=> example.com.            7200    IN      MX      10 mailhost.example.com.
      #
      def inspect
        data = get_inspect 
        # Returns the preformatted string
        if @name.size < 24
          [@name, @ttl.to_s, @cls.to_s, @type.to_s, 
            data].pack("A24 A8 A8 A8 A*")
        else
          to_a.join("   ")
        end
      end

      # Returns the RR in a string format.
      #
      #   mx = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #   mx.to_s
      #     #=> "example.com.            7200    IN      MX      10 mailhost.example.com."
      #
      def to_s
        "#{self.inspect}"
      end

      # Returns an array with all the fields for the RR record.
      #
      #   mx = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #   mx.to_a
      #     #=> ["example.com.",7200,"IN","MX","10 mailhost.example.com."]
      #
      def to_a
        [@name,@ttl,@cls.to_s,@type.to_s,get_inspect]
      end
      
      # Type accessor
      def type
        @type.to_s
      end
      
      # Class accessor
      def cls
        @cls.to_s
      end
      
      private
      
      #---
      # New RR with argument in string form
      #---
      def new_from_string(rrstring)

        unless rrstring =~ RR_REGEXP
          raise RRArgumentError, 
          "Format error for RR string (maybe CLASS and TYPE not valid?)"
        end

        # Name of RR - mandatory
        begin
          @name = $1.downcase
        rescue NoMethodError
          raise RRArgumentError, "Missing name field in RR string #{rrstring}"
        end
        
        # Time to live for RR, default 3 hours
        @ttl = $2 ? $2.to_i : 10800
        
        # RR class, default to IN
        @cls = Net::DNS::RR::Classes.new $3
        
        # RR type, default to A
        @type = Net::DNS::RR::Types.new $4
        
        # All the rest is data 
        @rdata = $5 ? $5.strip : ""  
        
        if self.class == Net::DNS::RR
          (eval "Net::DNS::RR::#@type").new(rrstring)
        else
          subclass_new_from_string(@rdata)
          self.class
        end
      end
      
      def new_from_hash(args)
        
        # Name field is mandatory   
        unless args.has_key? :name 
          raise RRArgumentError, "RR argument error: need at least RR name"
        end

        @name  = args[:name].downcase
        @ttl   = args[:ttl] ? args[:ttl].to_i : 10800 # Default 3 hours
        @type  = Net::DNS::RR::Types.new args[:type]
        @cls  = Net::DNS::RR::Classes.new args[:cls]
        
        @rdata = args[:rdata] ? args[:rdata].strip : ""
        @rdlength = args[:rdlength] || @rdata.size

        if self.class == Net::DNS::RR
          (eval "Net::DNS::RR::#@type").new(args)
        else
          hash = args - [:name,:ttl,:type,:cls]
          if hash.has_key? :rdata
            subclass_new_from_string(hash[:rdata])
          else
            subclass_new_from_hash(hash)
          end
          self.class
        end
      end # new_from_hash

      def new_from_binary(data,offset)
        if self.class == Net::DNS::RR
          temp = dn_expand(data,offset)[1]
          type = Net::DNS::RR::Types.new data.unpack("@#{temp} n")[0]
          (eval "Net::DNS::RR::#{type}").parse_packet(data,offset)
        else
          @name,offset = dn_expand(data,offset)
          rrtype,cls,@ttl,@rdlength = data.unpack("@#{offset} n2 N n")
          @type = Net::DNS::RR::Types.new rrtype
          @cls = Net::DNS::RR::Classes.new cls
          offset += RRFIXEDSZ
          offset = subclass_new_from_binary(data,offset)
          build_pack
          set_type
          return [self,offset]
        end
#      rescue StandardError => err
#        raise RRDataError, "Caught exception, maybe packet malformed: #{err}"
      end
      
      # Methods to be overridden by subclasses
      def subclass_new_from_array(arr)
      end
      def subclass_new_from_string(str)
      end
      def subclass_new_from_hash(hash)
      end
      def subclass_new_from_binary(data,offset)
      end
      def build_pack
      end
      def set_type
      end
      def get_inspect
        @rdata
      end
      def get_data
        @rdata
      end

      # NEW new method :)
      def self.new(*args)
        o = allocate
        obj = o.send(:initialize,*args)
        if self == Net::DNS::RR
          return obj
        else
          return o
        end
      end
            
    end # class RR
    
  end # module DNS
end # module Net

class RRArgumentError < ArgumentError # :nodoc:
end
class RRDataError < StandardError # :nodoc:
end

module ExtendHash # :nodoc:
  
  # Performs a sort of group difference 
  # operation on hashes or arrays
  # 
  #   a = {:a=>1,:b=>2,:c=>3}
  #   b = {:a=>1,:b=>2}
  #   c = [:a,:c]
  #   a-b #=> {:c=>3}
  #   a-c #=> {:b=>2}
  #
  def -(oth)
    case oth
    when Hash
      delete_if {|k,v| oth.has_key? k}
    when Array
      delete_if {|k,v| oth.include? k}
    end
  end
end

class Hash # :nodoc:
  include ExtendHash
end

