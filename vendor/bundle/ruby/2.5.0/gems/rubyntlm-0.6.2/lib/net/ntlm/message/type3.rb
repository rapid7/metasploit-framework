module Net
  module NTLM
    class Message

      # @private false
      class Type3 < Message

        string          :sign,          {:size => 8, :value => SSP_SIGN}
        int32LE         :type,          {:value => 3}
        security_buffer :lm_response,   {:value => ""}
        security_buffer :ntlm_response, {:value => ""}
        security_buffer :domain,        {:value => ""}
        security_buffer :user,          {:value => ""}
        security_buffer :workstation,   {:value => ""}
        security_buffer :session_key,   {:value => "", :active => false }
        int32LE         :flag,          {:value => 0, :active => false }
        string          :os_version,    {:size => 8, :active => false }

        class << Type3
          # Builds a Type 3 packet
          # @note All options must be properly encoded with either unicode or oem encoding
          # @return [Type3]
          # @option arg [String] :lm_response The LM hash
          # @option arg [String] :ntlm_response The NTLM hash
          # @option arg [String] :domain The domain to authenticate to
          # @option arg [String] :workstation The name of the calling workstation
          # @option arg [String] :session_key The session key
          # @option arg [Integer] :flag Flags for the packet
          def create(arg, opt ={})
            t = new
            t.lm_response = arg[:lm_response]
            t.ntlm_response = arg[:ntlm_response]
            t.domain = arg[:domain]
            t.user = arg[:user]

            if arg[:workstation]
              t.workstation = arg[:workstation]
            end

            if arg[:session_key]
              t.enable(:session_key)
              t.session_key = arg[:session_key]
            end

            if arg[:flag]
              t.enable(:session_key)
              t.enable(:flag)
              t.flag = arg[:flag]
            end
            t
          end
        end

        # @param server_challenge (see #password?)
        def blank_password?(server_challenge)
          password?('', server_challenge)
        end

        # @param password [String]
        # @param server_challenge [String] The server's {Type2#challenge challenge} from the
        #   {Type2} message for which this object is a response.
        # @return [true] if +password+ was the password used to generate this
        #   {Type3} message
        # @return [false] otherwise
        def password?(password, server_challenge)
          case ntlm_version
          when :ntlm2_session
            ntlm2_session_password?(password, server_challenge)
          when :ntlmv2
            ntlmv2_password?(password, server_challenge)
          else
            raise
          end
        end

        # @return [Symbol]
        def ntlm_version
          if ntlm_response.size == 24 && lm_response[0,8] != "\x00"*8 && lm_response[8,16] == "\x00"*16
            :ntlm2_session
          elsif ntlm_response.size == 24
            :ntlmv1
          elsif ntlm_response.size > 24
            :ntlmv2
          end
        end

        private

        def ntlm2_session_password?(password, server_challenge)
          hash = ntlm_response
          _lm, empty_hash = NTLM.ntlm2_session(
            {
              :ntlm_hash => NTLM.ntlm_hash(password),
              :challenge => server_challenge,
            },
            {
              :client_challenge => lm_response[0,8]
            }
          )
          hash == empty_hash
        end

        def ntlmv2_password?(password, server_challenge)

          # The first 16 bytes of the ntlm_response are the HMAC of the blob
          # that follows it.
          blob = Blob.new
          blob.parse(ntlm_response[16..-1])

          empty_hash = NTLM.ntlmv2_response(
            {
              # user and domain came from the serialized data here, so
              # they're already unicode
              :ntlmv2_hash => NTLM.ntlmv2_hash(user, '', domain, :unicode => true),
              :challenge => server_challenge,
              :target_info => blob.target_info
            },
            {
              :client_challenge => blob.challenge,
              # The blob's timestamp is already in milliseconds since 1601,
              # so convert it back to epoch time first
              :timestamp => (blob.timestamp / 10_000_000) - NTLM::TIME_OFFSET,
            }
          )

          empty_hash == ntlm_response
        end
      end
    end
  end
end
