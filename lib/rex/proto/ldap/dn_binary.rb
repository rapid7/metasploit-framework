module Rex
  module Proto
    module LDAP

      # Handle converting objects into the DN-Binary syntax
      # See: https://learn.microsoft.com/en-us/windows/win32/adschema/s-object-dn-binary
      class DnBinary
        def initialize(dn, data)
          self.dn = dn
          self.data = data
        end

        # Turn a DN-Binary string into a structured object containing data and a DN
        # @param str [String] A DN-Binary-formatted string
        def self.decode(str)
          groups = str.match(/B:(\d+):(([a-fA-F0-9]{2})*):(.*)/)
          raise ArgumentError.new('Invalid DN Binary string') if groups.nil?
          length = groups[1].to_i
          raise ArgumentError.new('Invalid DN Binary string length') if groups[2].length != length
          data = [groups[2]].pack('H*')

          DnBinary.new(groups[4], data)
        end

        # Turn this structured object containing data and a DN into a DN-Binary string 
        # @return [String] The DN-Binary-formatted string
        def encode
          data_hex = self.data.unpack('H*')[0]

          "B:#{data_hex.length}:#{data_hex}:#{self.dn}"
        end

        attr_accessor :data # Raw bytes
        attr_accessor :dn # LDAP Distinguished name
      end
    end
  end
end