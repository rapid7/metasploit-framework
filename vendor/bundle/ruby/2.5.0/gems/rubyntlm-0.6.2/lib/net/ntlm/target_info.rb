module Net
  module NTLM

    # Represents a list of AV_PAIR structures
    # @see https://msdn.microsoft.com/en-us/library/cc236646.aspx
    class TargetInfo

      # Allowed AvId values for an AV_PAIR
      MSV_AV_EOL               = "\x00\x00".freeze
      MSV_AV_NB_COMPUTER_NAME  = "\x01\x00".freeze
      MSV_AV_NB_DOMAIN_NAME    = "\x02\x00".freeze
      MSV_AV_DNS_COMPUTER_NAME = "\x03\x00".freeze
      MSV_AV_DNS_DOMAIN_NAME   = "\x04\x00".freeze
      MSV_AV_DNS_TREE_NAME     = "\x05\x00".freeze
      MSV_AV_FLAGS             = "\x06\x00".freeze
      MSV_AV_TIMESTAMP         = "\x07\x00".freeze
      MSV_AV_SINGLE_HOST       = "\x08\x00".freeze
      MSV_AV_TARGET_NAME       = "\x09\x00".freeze
      MSV_AV_CHANNEL_BINDINGS  = "\x0A\x00".freeze

      # @param av_pair_sequence [String] AV_PAIR list from challenge message
      def initialize(av_pair_sequence)
        @av_pairs = read_pairs(av_pair_sequence)
      end

      attr_reader :av_pairs

      def to_s
        result = ''
        av_pairs.each do |k,v|
          result << k
          result << [v.length].pack('S')
          result << v
        end
        result << Net::NTLM::TargetInfo::MSV_AV_EOL
        result << [0].pack('S')
        result.force_encoding(Encoding::ASCII_8BIT)
      end

      private

      VALID_PAIR_ID = [
          MSV_AV_EOL,
          MSV_AV_NB_COMPUTER_NAME,
          MSV_AV_NB_DOMAIN_NAME,
          MSV_AV_DNS_COMPUTER_NAME,
          MSV_AV_DNS_DOMAIN_NAME,
          MSV_AV_DNS_TREE_NAME,
          MSV_AV_FLAGS,
          MSV_AV_TIMESTAMP,
          MSV_AV_SINGLE_HOST,
          MSV_AV_TARGET_NAME,
          MSV_AV_CHANNEL_BINDINGS
      ].freeze

      def read_pairs(av_pair_sequence)
        offset = 0
        result = {}
        return result if av_pair_sequence.nil?

        until offset >= av_pair_sequence.length
          id = av_pair_sequence[offset..offset+1]

          unless VALID_PAIR_ID.include?(id)
            raise Net::NTLM::InvalidTargetDataError.new( 
              "Invalid AvId #{to_hex(id)} in AV_PAIR structure",
              av_pair_sequence
            )
          end

          length = av_pair_sequence[offset+2..offset+3].unpack('S')[0].to_i
          if length > 0
            value = av_pair_sequence[offset+4..offset+4+length-1]
            result[id] = value
          end

          offset += 4 + length
        end

        result
      end

      def to_hex(str)
        return nil if str.nil?
        str.bytes.map {|b| '0x' + b.to_s(16).rjust(2,'0').upcase}.join('-')
      end
    end
  end
end
