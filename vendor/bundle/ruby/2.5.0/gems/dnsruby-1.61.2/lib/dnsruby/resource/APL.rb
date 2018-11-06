module Dnsruby
  class Prefix
    Regex = %r{\A([!])?([12]):(.*)/(\d+)\z}
    attr_reader :af, :prefix_length, :negative, :address_lenght, :address
    class << self
      def create(prefix) #:nodoc:
        unless md = Regex.match(prefix)
          raise ArgumentError.new('APL format error')
        end
        negative=md[1]
        af = md[2].to_i
        prefix_length = md[4].to_i
        case af
        when 1
          if prefix_length > 32 ||
             prefix_length < 0
            raise ArgumentError.new('APL IPv4 prefix format error')
          end
          address = IPv4.create(md[3])
        when 2
          if prefix_length > 128 ||
             prefix_length < 0
            raise ArgumentError.new('APL IPv6 prefix format error')
          end
          address = IPv6.create(md[3])
        else
          raise ArgumentError.new('APL address family error')
        end
        address_length = (prefix_length / 8.0).ceil

        Prefix.new(af, prefix_length, negative, address_length, address)
      end
    end
    def initialize(af, prefix_length, negative, address_length, address)
      @af = af
      @prefix_length = prefix_length
      @negative = negative
      @address_length = address_length
      @address = address
      @flag = address_length
      @flag |= 0x80 if @negative
    end

    def to_s
      "#{@negative}#{@af}:#{@address}/#{@prefix_length}"
    end

    def put_msg(msg) #:nodoc: all
      msg.put_pack('nCC',@af,@prefix_length,@flag)
      msg.put_bytes(@address.address[0,@address_length])
    end
  end
  class Prefixes
    attr_accessor :prefixes
    class << self
        def create(arg)
          case arg
          when Prefixes
            return arg
          when String
            prefixes = arg.split(/\s/).map { |prefix| Prefix.create(prefix) }
          when Array
            prefixes = arg.map { |prefix| Prefix.create(prefix) }
          else
            raise ArgumentError.new("APL format erro #{arg}")
          end
          Prefixes.new(prefixes)
        end
        def create_from_message(msg)
          prefixes = []
          while(msg.has_remaining?) do
            negative = nil
            af,prefix_length,flag = msg.get_unpack('nCC')
            negative = '!' if 0x80 & flag == 0x80
            address_length = flag & 0x7f

            case(af)
            when 1
              addr = msg.get_bytes(address_length) + "\0" * (4 - address_length)
              address = IPv4.new(addr)
            when 2
              addr = msg.get_bytes(address_length) + "\0" * (16 - address_length)
              address = IPv6.new(addr)
            else
              raise ArgumentError.new("APL format error")
            end
            prefixes.push(Prefix.new(af, prefix_length, negative, address_length, address))
          end

          Prefixes.new(prefixes)
        end
    end
    def initialize(prefixes)
      @prefixes = prefixes
    end

    def to_s
      @prefixes.map(&:to_s).join(' ')
    end

    def encode_rdata(msg, _canonical = false) #:nodoc: all
      @prefixes.each do |prefix|
        prefix.put_msg(msg)
      end
    end
  end
  class RR
    module IN
      # Class for DNS Address (A) resource records.
      #
      # RFC 1035 Section 3.4.1
      class APL < RR
        ClassHash[[TypeValue = Types::APL, ClassValue = ClassValue]] = self #:nodoc: all

        # The RR's (Resolv::IPv4) address field
        attr_accessor :prefixes

        def from_data(data) #:nodoc: all
          @prefixes = Prefixes.create(data)
        end

        # Create the RR from a hash
        def from_hash(hash)
          @prefixes = Prefixes.create(hash[:prefixes])
        end

        #  Create the RR from a standard string
        def from_string(input)
          @prefixes = Prefixes.create(input)
        end

        def rdata_to_string
          @prefixes.to_s
        end

        def encode_rdata(msg, canonical = false) #:nodoc: all
          @prefixes.encode_rdata(msg,canonical)
        end

        def self.decode_rdata(msg) #:nodoc: all
          new(Prefixes.create_from_message(msg))
        end
      end
    end
  end
end
