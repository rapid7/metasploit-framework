module Net
  module NTLM
    class ChannelBinding

      # Creates a ChannelBinding used for Extended Protection Authentication
      # @see http://blogs.msdn.com/b/openspecification/archive/2013/03/26/ntlm-and-channel-binding-hash-aka-exteneded-protection-for-authentication.aspx
      #
      # @param outer_channel [OpenSSL::X509::Certificate] Server certificate securing
      #   the outer TLS channel
      # @return [NTLM::ChannelBinding] A ChannelBinding holding a token that can be
      #   embedded in a {Type3} message
      def self.create(outer_channel)
        new(outer_channel)
      end

      # @param outer_channel [OpenSSL::X509::Certificate] Server certificate securing
      #   the outer TLS channel
      def initialize(outer_channel)
        @channel = outer_channel
        @unique_prefix = 'tls-server-end-point'
        @initiator_addtype = 0
        @initiator_address_length = 0
        @acceptor_addrtype = 0
        @acceptor_address_length = 0
      end

      attr_reader :channel, :unique_prefix, :initiator_addtype
      attr_reader :initiator_address_length, :acceptor_addrtype
      attr_reader :acceptor_address_length

      # Returns a channel binding hash acceptable for use as a AV_PAIR MsvAvChannelBindings
      #   field value as specified in the NTLM protocol
      #
      # @return [String] MD5 hash of gss_channel_bindings_struct
      def channel_binding_token
        @channel_binding_token ||= OpenSSL::Digest::MD5.new(gss_channel_bindings_struct).digest
      end

      def gss_channel_bindings_struct
        @gss_channel_bindings_struct ||= begin
          token = [initiator_addtype].pack('I')
          token << [initiator_address_length].pack('I')
          token << [acceptor_addrtype].pack('I')
          token << [acceptor_address_length].pack('I')
          token << [application_data.length].pack('I')
          token << application_data
          token
        end
      end

      def channel_hash
        @channel_hash ||= OpenSSL::Digest::SHA256.new(channel.to_der)
      end

      def application_data
        @application_data ||= begin
          data = unique_prefix
          data << ':'
          data << channel_hash.digest
          data
        end
      end
    end
  end
end
