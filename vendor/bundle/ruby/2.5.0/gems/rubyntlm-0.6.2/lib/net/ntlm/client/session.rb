module Net
  module NTLM
    class Client::Session

      VERSION_MAGIC = "\x01\x00\x00\x00"
      TIME_OFFSET   = 11644473600
      MAX64         = 0xffffffffffffffff
      CLIENT_TO_SERVER_SIGNING = "session key to client-to-server signing key magic constant\0"
      SERVER_TO_CLIENT_SIGNING = "session key to server-to-client signing key magic constant\0"
      CLIENT_TO_SERVER_SEALING = "session key to client-to-server sealing key magic constant\0"
      SERVER_TO_CLIENT_SEALING = "session key to server-to-client sealing key magic constant\0"

      attr_reader :client, :challenge_message, :channel_binding

      # @param client [Net::NTLM::Client] the client instance
      # @param challenge_message [Net::NTLM::Message::Type2] server message
      def initialize(client, challenge_message, channel_binding = nil)
        @client = client
        @challenge_message = challenge_message
        @channel_binding = channel_binding
      end

      # Generate an NTLMv2 AUTHENTICATE_MESSAGE
      # @see http://msdn.microsoft.com/en-us/library/cc236643.aspx
      # @return [Net::NTLM::Message::Type3]
      def authenticate!
        calculate_user_session_key!
        type3_opts = {
          :lm_response   => lmv2_resp,
          :ntlm_response => ntlmv2_resp,
          :domain        => domain,
          :user          => username,
          :workstation   => workstation,
          :flag          => (challenge_message.flag & client.flags)
        }
        t3 = Message::Type3.create type3_opts
        if negotiate_key_exchange?
          t3.enable(:session_key)
          rc4 = OpenSSL::Cipher.new("rc4")
          rc4.encrypt
          rc4.key = user_session_key
          sk = rc4.update exported_session_key
          sk << rc4.final
          t3.session_key = sk
        end
        t3
      end

      def exported_session_key
        @exported_session_key ||=
          begin
            if negotiate_key_exchange?
              OpenSSL::Cipher.new("rc4").random_key
            else
              user_session_key
            end
          end
      end

      def sign_message(message)
        seq = sequence
        sig = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, client_sign_key, "#{seq}#{message}")[0..7]
        if negotiate_key_exchange?
          sig = client_cipher.update sig
          sig << client_cipher.final
        end
        "#{VERSION_MAGIC}#{sig}#{seq}"
      end

      def verify_signature(signature, message)
        seq = signature[-4..-1]
        sig = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, server_sign_key, "#{seq}#{message}")[0..7]
        if negotiate_key_exchange?
          sig = server_cipher.update sig
          sig << server_cipher.final
        end
        "#{VERSION_MAGIC}#{sig}#{seq}" == signature
      end

      def seal_message(message)
        emessage = client_cipher.update(message)
        emessage + client_cipher.final
      end

      def unseal_message(emessage)
        message = server_cipher.update(emessage)
        message + server_cipher.final
      end

      private


      def user_session_key
        @user_session_key ||=  nil
      end

      def sequence
        [raw_sequence].pack("V*")
      end

      def raw_sequence
        if defined? @raw_sequence
          @raw_sequence += 1
        else
          @raw_sequence = 0
        end
      end

      def client_sign_key
        @client_sign_key ||= OpenSSL::Digest::MD5.digest "#{exported_session_key}#{CLIENT_TO_SERVER_SIGNING}"
      end

      def server_sign_key
        @server_sign_key ||= OpenSSL::Digest::MD5.digest "#{exported_session_key}#{SERVER_TO_CLIENT_SIGNING}"
      end

      def client_seal_key
        @client_seal_key ||= OpenSSL::Digest::MD5.digest "#{exported_session_key}#{CLIENT_TO_SERVER_SEALING}"
      end

      def server_seal_key
        @server_seal_key ||= OpenSSL::Digest::MD5.digest "#{exported_session_key}#{SERVER_TO_CLIENT_SEALING}"
      end

      def client_cipher
        @client_cipher ||=
          begin
            rc4 = OpenSSL::Cipher.new("rc4")
            rc4.encrypt
            rc4.key = client_seal_key
            rc4
          end
      end

      def server_cipher
        @server_cipher ||=
          begin
            rc4 = OpenSSL::Cipher.new("rc4")
            rc4.decrypt
            rc4.key = server_seal_key
            rc4
          end
      end

      def client_challenge
        @client_challenge ||= NTLM.pack_int64le(rand(MAX64))
      end

      def server_challenge
        @server_challenge ||= challenge_message[:challenge].serialize
      end

      # epoch -> milsec from Jan 1, 1601
      # @see http://support.microsoft.com/kb/188768
      def timestamp
        @timestamp ||= 10_000_000 * (Time.now.to_i + TIME_OFFSET)
      end

      def use_oem_strings?
        challenge_message.has_flag? :OEM
      end

      def negotiate_key_exchange?
        challenge_message.has_flag? :KEY_EXCHANGE
      end

      def username
        oem_or_unicode_str client.username
      end

      def password
        oem_or_unicode_str client.password
      end

      def workstation
        (client.workstation ? oem_or_unicode_str(client.workstation) : "")
      end

      def domain
        (client.domain ? oem_or_unicode_str(client.domain) : "")
      end

      def oem_or_unicode_str(str)
        if use_oem_strings?
          NTLM::EncodeUtil.decode_utf16le str
        else
          NTLM::EncodeUtil.encode_utf16le str
        end
      end

      def ntlmv2_hash
        @ntlmv2_hash ||= NTLM.ntlmv2_hash(username, password, domain, {:client_challenge => client_challenge, :unicode => !use_oem_strings?})
      end

      def calculate_user_session_key!
        @user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, nt_proof_str)
      end

      def lmv2_resp
        OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, server_challenge + client_challenge) + client_challenge
      end

      def ntlmv2_resp
        nt_proof_str + blob
      end

      def nt_proof_str
        @nt_proof_str ||= OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, server_challenge + blob)
      end

      def blob
        @blob ||=
          begin
            b = Blob.new
            b.timestamp = timestamp
            b.challenge = client_challenge
            b.target_info = target_info
            b.serialize
          end
      end

      def target_info
        @target_info ||= begin
          if channel_binding
            t = Net::NTLM::TargetInfo.new(challenge_message.target_info)
            av_id = Net::NTLM::TargetInfo::MSV_AV_CHANNEL_BINDINGS
            t.av_pairs[av_id] = channel_binding.channel_binding_token
            t.to_s
          else
            challenge_message.target_info
          end
        end
      end

    end
  end
end
