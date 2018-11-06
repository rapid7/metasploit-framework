require 'openssl'

module Dnsruby
  class RR
    module IN
      # Class for DNS TLSA server certificate or public key (TLSA) resource records.
      #
      # RFC 6698
      class TLSA < RR
        ClassHash[[TypeValue = Types::TLSA, ClassValue = ClassValue]] = self #:nodoc: all
        # sec 2.1.1 ,7,2
        #
        # 0 CA constraint
        # 1 Service certificate constraint
        # 2 Trust anchor assertion
        # 3 Domain-issued certificate
        # 4-254 Unassigned
        # 255 Private use
        attr_accessor :usage
        # sec 2.1.2, 7.3
        #
        # 0 Full certificate
        # 1 SubjectPublicKeyInfo
        # 2-254 Unassigned
        # 255 Private use
        attr_accessor :selector
        # sec 2.3.1
        #
        # 0 Exact match on selected content
        # 1 SHA-256 hash of selected content
        # 2 SHA-512 hash of selected content
        # 3-254 Unassigned
        # 255 Private use
        attr_accessor :matching_type
        # sec 2.1.4
        attr_accessor :data
        attr_accessor :databin

        def verify
          raise ArgumentError, "usage with invalid value: #{@usage}" if @usage < 0 || @usage > 255
          raise ArgumentError, "selector with invalid value: #{@selector}" if @selector < 0 || @selector > 255
          raise ArgumentError, "matching_type with invalid value: #{@matching_type}" if @matching_type < 0 || @matching_type > 255
          raise ArgumentError, "data with invalid value: #{@data}" if (@matching_type == 1 && @databin.bytesize != 32) || (@matching_type == 2 && @databin.bytesize != 64)
          pkey if @matching_type == 0
        end

        def from_data(data) #:nodoc: all
          self.usage = data[0]
          self.selector = data[1]
          self.matching_type = data[2]
          self.databin = data[3]
          verify
        end

        # Create the RR from a hash
        def from_hash(hash)
          super(hash)
          verify
        end

        def data=(data)
          self.databin = parse_string(data)
        end

        def databin=(databin)
          @databin = databin
          @data = @databin.unpack('H*')[0].each_char.each_slice(57).map(&:join).join(' ')
        end

        def cert
          if @matching_type == 0 && @selector == 0 && @databin
            begin
              cert = OpenSSL::X509::Certificate.new(@databin)
            rescue => e
              raise ArgumentError, 'data is invalid cert '
            end
          end
          cert
        end

        def pkey
          pubkey = nil
          if @matching_type == 0 && @databin
            if @selector == 0
              cert = self.cert
              pubkey = cert.public_key
            elsif @selector == 1
              begin
                pubkey = OpenSSL::PKey.read(@databin)
              rescue
                raise ArgumentError, 'data is invalid pkey'
              end
            end
          end
          pubkey
        end

        def parse_string(data)
          buf = ''
          comment = false
          multiline = false
          data.each_char do |ch|
            case ch
            when ';' then comment = true
            when '\n'
              raise ArgumentError, 'string format error' unless multiline
              comment = false
            when '\r' then next
            when ' ' then next
            when comment then next
            when '(' then multiline = true
            when ')' then multiline = false
            else
              buf += ch
            end
          end
          raise ArgumentError, 'string format error' if multiline

          [buf].pack('H*')
        end

        #  Create the RR from a standard string
        def from_string(input)
          values = input.split(' ', 4)
          self.usage = values[0].to_i
          self.selector = values[1].to_i
          self.matching_type = values[2].to_i
          self.data = values[3]
          verify
        end

        def rdata_to_string
          "#{@usage} #{@selector} #{@matching_type} #{@data}"
        end

        def encode_rdata(msg, _canonical = false) #:nodoc: all
          msg.put_pack('CCC', @usage, @selector, @matching_type)
          msg.put_bytes(@databin)
        end

        def self.decode_rdata(msg) #:nodoc: all
          usage, selector, matching_type = msg.get_unpack('CCC')
          databin = msg.get_bytes
          new([usage, selector, matching_type, databin])
        end
      end
    end
  end
end
