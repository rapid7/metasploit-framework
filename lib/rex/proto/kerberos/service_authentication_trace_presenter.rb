# frozen_string_literal: true

require 'rex/proto/gss'
require 'rex/proto/kerberos/gss_token_parser'
require 'rex/proto/kerberos/kerberos_readable_text_presenter'
require 'rex/proto/kerberos/kerberos_trace_serializer'

module Rex
  module Proto
    module Kerberos
      # Presents Kerberos service-authentication, GSS/SPNEGO, and carrier trace events.
      class ServiceAuthenticationTracePresenter
        TRACE_MODE_FULL = 'full'

        # @param trace_mode [String]
        # @param token_parser [Rex::Proto::Kerberos::GssTokenParser]
        # @param serializer [Rex::Proto::Kerberos::KerberosTraceSerializer]
        # @param readable_text_presenter [Rex::Proto::Kerberos::KerberosReadableTextPresenter]
        def initialize(
          trace_mode:,
          token_parser: GssTokenParser.new,
          serializer: KerberosTraceSerializer.new,
          readable_text_presenter: KerberosReadableTextPresenter.new
        )
          @trace_mode = trace_mode
          @token_parser = token_parser
          @serializer = serializer
          @readable_text_presenter = readable_text_presenter
        end

        # @param metadata [Hash]
        # @return [String]
        def present_ap_req(metadata)
          present_hash(ap_req_trace_hash(metadata, full: full_trace?))
        rescue StandardError => e
          "AP-REQ trace rendering error: #{e.class}: #{e.message}"
        end

        # @param metadata [Hash]
        # @return [String]
        def present_gss_token(metadata)
          present_hash(gss_token_trace_hash(metadata))
        rescue StandardError => e
          "GSS token trace rendering error: #{e.class}: #{e.message}"
        end

        # @param metadata [Hash]
        # @return [String]
        def present_spnego_token(metadata)
          present_hash(spnego_token_trace_hash(metadata))
        rescue StandardError => e
          "SPNEGO token trace rendering error: #{e.class}: #{e.message}"
        end

        # @param metadata [Hash]
        # @return [String]
        def present_response_token(metadata)
          present_hash(response_token_trace_hash(metadata))
        rescue StandardError => e
          "Response token trace rendering error: #{e.class}: #{e.message}"
        end

        private

        def present_hash(hash)
          @readable_text_presenter.present(serialize_trace_value(hash, redact_binary: !full_trace?))
        end

        def full_trace?
          @trace_mode == TRACE_MODE_FULL
        end

        def ap_req_trace_hash(metadata, full:)
          ap_req = metadata[:ap_req]
          authenticator = metadata[:authenticator]
          credential = metadata[:credential]
          ticket = metadata[:ticket] || ap_req&.ticket
          encrypted_authenticator = ap_req&.authenticator

          hash = {
            'ap_req' => compact_hash(
              'message_type' => format_message_type_value(ap_req&.msg_type || Rex::Proto::Kerberos::Model::AP_REQ),
              'pvno' => ap_req&.pvno,
              'ap_options' => format_ap_options(ap_req&.options),
              'mutual_authentication' => metadata[:mutual_auth] ? 'requested' : 'not requested',
              'key_usage' => metadata[:use_subkey] ? 'authenticator subkey' : 'service ticket session key'
            ),
            'principal' => compact_hash(
              'client_principal' => metadata[:client_principal] || principal_with_realm(authenticator&.cname, authenticator&.crealm),
              'service_principal' => metadata[:service_principal] || principal_with_realm(ticket&.sname, ticket&.realm),
              'spn' => metadata[:spn] || principal_to_s(ticket&.sname),
              'realm' => metadata[:realm] || ticket&.realm || authenticator&.crealm
            ),
            'selected_service_ticket' => compact_hash(
              'server' => credential&.server&.to_s || principal_with_realm(ticket&.sname, ticket&.realm),
              'client' => credential&.client&.to_s || metadata[:client_principal],
              'ticket_etype' => format_encryption_type(ticket&.enc_part&.etype || metadata[:ticket_encryption_type]),
              'ticket_flags' => format_flags(metadata[:ticket_flags] || credential&.ticket_flags),
              'ticket_length' => credential&.ticket&.length || encoded_length(ticket),
              'times' => ticket_times_hash(metadata, credential)
            ),
            'authenticator' => compact_hash(
              'encryption_type' => format_encryption_type(encrypted_authenticator&.etype || metadata[:session_key]&.type),
              'checksum_type' => authenticator&.checksum&.type,
              'checksum' => binary_summary(authenticator&.checksum&.checksum),
              'subkey' => encryption_key_summary(authenticator&.subkey),
              'sequence_number' => authenticator&.sequence_number || metadata[:sequence_number]
            ),
            'gss_context' => compact_hash(
              'replay_detection' => metadata[:replay_detection],
              'channel_binding' => metadata[:channel_binding],
              'delegated_credentials' => metadata[:delegated_credentials]
            )
          }

          if full
            hash['ap_req_message'] = @serializer.serialize(ap_req, redact_binary: false) if ap_req
            hash['decrypted_authenticator'] = @serializer.serialize(authenticator, redact_binary: false) if authenticator
            hash['session_key'] = encryption_key_summary(metadata[:session_key], redact_binary: false) if metadata[:session_key]
          end

          compact_nested_hash(hash)
        end

        def gss_token_trace_hash(metadata)
          token = @token_parser.binary_string(metadata[:token])
          parsed = @token_parser.parse_kerberos(token)
          ap_req_der = metadata[:ap_req_der]
          ap_req_payload = parsed[:ap_req_payload]

          compact_nested_hash(
            'wrapper_type' => 'GSS-Kerberos',
            'direction' => metadata[:direction] || 'outbound',
            'mechanism_oid' => parsed[:mechanism_oid] || metadata[:mechanism_oid] || Rex::Proto::Gss::OID_KERBEROS_5.value,
            'inner_token_type' => parsed[:inner_token_type] || metadata[:inner_token_type],
            'ap_req_payload_length' => (ap_req_payload || ap_req_der)&.bytesize,
            'final_token_length' => token&.bytesize,
            'ap_req_payload_matches' => ap_req_der && ap_req_payload ? ap_req_der == ap_req_payload : nil,
            'token' => binary_summary(token),
            'service_principal' => metadata[:service_principal],
            'realm' => metadata[:realm],
            'mutual_authentication' => metadata[:mutual_auth] ? 'requested' : 'not requested',
            'parse_failure' => parsed[:parse_failure]
          )
        end

        def spnego_token_trace_hash(metadata)
          token = @token_parser.binary_string(metadata[:token])
          parsed = @token_parser.parse_spnego_init(token)
          mech_token = parsed[:mech_token]
          inner = mech_token ? gss_token_trace_hash(metadata.merge(token: mech_token, direction: metadata[:direction])) : nil

          compact_nested_hash(
            'wrapper_type' => 'SPNEGO NegTokenInit',
            'direction' => metadata[:direction] || 'outbound',
            'mechanism_oid' => Rex::Proto::Gss::OID_SPNEGO.value,
            'mech_types' => parsed[:mech_types],
            'preferred_mech' => parsed[:preferred_mech],
            'optimistic_mech_token' => !mech_token.nil?,
            'mech_token_length' => mech_token&.bytesize,
            'req_flags' => parsed[:req_flags],
            'mech_list_mic' => binary_summary(parsed[:mech_list_mic]),
            'final_token_length' => token&.bytesize,
            'token' => binary_summary(token),
            'inner_ap_req' => inner,
            'service_principal' => metadata[:service_principal],
            'realm' => metadata[:realm],
            'mutual_authentication' => metadata[:mutual_auth] ? 'requested' : 'not requested',
            'parse_failure' => parsed[:parse_failure]
          )
        end

        def response_token_trace_hash(metadata)
          token = @token_parser.binary_string(metadata[:token])
          token_type = metadata[:token_type]
          parsed = if metadata[:parse_failure]
                     if metadata[:message]
                       kerberos_response_message_hash(metadata[:message], metadata[:decrypted_part], full: full_trace?).merge(
                         'parse_failure' => metadata[:parse_failure]
                       )
                     else
                       { parse_failure: metadata[:parse_failure] }
                     end
                   elsif token_type == 'SPNEGO NegTokenResp'
                     spnego_response_trace_hash(token)
                   elsif metadata[:message]
                     kerberos_response_message_hash(metadata[:message], metadata[:decrypted_part], full: full_trace?)
                   else
                     gss_response_trace_hash(token, metadata[:session_key])
                   end

          compact_nested_hash(
            'wrapper_type' => token_type,
            'direction' => metadata[:direction] || 'inbound',
            'carrier' => metadata[:carrier],
            'token_length' => token&.bytesize,
            'token' => binary_summary(token),
            'response' => parsed,
            'service_principal' => metadata[:service_principal],
            'realm' => metadata[:realm],
            'mutual_authentication' => metadata[:mutual_authentication]
          )
        end

        def spnego_response_trace_hash(token)
          parsed = @token_parser.parse_spnego_response(token)
          return { 'parse_failure' => parsed[:parse_failure] } if parsed[:parse_failure]

          response_token = parsed[:response_token]
          compact_nested_hash(
            'wrapper_type' => 'SPNEGO NegTokenResp',
            'neg_state' => parsed[:neg_state],
            'supported_mech' => parsed[:supported_mech],
            'response_token_length' => response_token&.bytesize,
            'mech_list_mic' => binary_summary(parsed[:mech_list_mic]),
            'inner_response' => response_token ? gss_response_trace_hash(response_token, nil) : nil
          )
        end

        def gss_response_trace_hash(token, session_key)
          parsed = @token_parser.parse_kerberos(token)
          if parsed[:parse_failure]
            return {
              'parse_failure' => "unable to parse response token as AP-REP/KRB-ERROR/SPNEGO: #{parsed[:parse_failure]}"
            }
          end

          case parsed[:inner_token_type]
          when 'AP-REP'
            ap_rep = Rex::Proto::Kerberos::Model::ApRep.decode(parsed[:response_payload])
            decrypted_part = decrypt_ap_rep_for_trace(ap_rep, session_key)
            kerberos_response_message_hash(ap_rep, decrypted_part, full: full_trace?)
          when 'KRB-ERROR'
            krb_error = Rex::Proto::Kerberos::Model::KrbError.decode(parsed[:response_payload])
            kerberos_response_message_hash(krb_error, nil, full: full_trace?)
          else
            {
              'parse_failure' => "unable to parse response token as AP-REP/KRB-ERROR/SPNEGO: unknown token id #{parsed[:token_id].inspect}",
              'mechanism_oid' => parsed[:mechanism_oid],
              'token_id' => parsed[:token_id]
            }
          end
        rescue StandardError => e
          { 'parse_failure' => "unable to parse response token as AP-REP/KRB-ERROR/SPNEGO: #{e.class}: #{e.message}" }
        end

        def kerberos_response_message_hash(message, decrypted_part, full:)
          case message
          when Rex::Proto::Kerberos::Model::ApRep
            hash = {
              'message_type' => format_message_type_value(message.msg_type),
              'encrypted_part' => compact_hash(
                'etype' => format_encryption_type(message.enc_part&.etype),
                'cipher' => binary_summary(message.enc_part&.cipher)
              ),
              'decrypted_part' => decrypted_ap_rep_part_hash(decrypted_part)
            }
            hash['ap_rep_message'] = @serializer.serialize(message, redact_binary: false) if full
            compact_nested_hash(hash)
          when Rex::Proto::Kerberos::Model::KrbError
            hash = {
              'message_type' => format_message_type_value(message.msg_type),
              'error_code' => @serializer.serialize_value(message.error_code, redact_binary: !full_trace?),
              'realm' => message.realm,
              'server_principal' => principal_with_realm(message.sname, message.realm),
              'error_text' => message.etext,
              'error_data' => binary_summary(message.e_data),
              'server_time' => message.stime,
              'server_microseconds' => message.susec,
              'client_time' => message.ctime,
              'client_microseconds' => message.cusec
            }
            hash['krb_error_message'] = @serializer.serialize(message, redact_binary: false) if full
            compact_nested_hash(hash)
          else
            { 'message' => message.to_s }
          end
        end

        def decrypted_ap_rep_part_hash(decrypted_part)
          return nil if decrypted_part.nil?
          return { 'parse_failure' => decrypted_part[:parse_failure] } if decrypted_part.is_a?(Hash) && decrypted_part[:parse_failure]

          compact_hash(
            'subkey' => encryption_key_summary(decrypted_part.subkey),
            'sequence_number' => decrypted_part.sequence_number,
            'client_time' => decrypted_part.ctime,
            'client_microseconds' => decrypted_part.cusec
          )
        end

        def decrypt_ap_rep_for_trace(ap_rep, session_key)
          return nil if session_key.nil?
          return { parse_failure: 'unable to decrypt AP-REP without matching session key etype' } if session_key.type != ap_rep.enc_part.etype

          ap_rep.decrypt_enc_part(session_key.value)
        rescue StandardError => e
          { parse_failure: "unable to decrypt AP-REP encrypted part: #{e.class}: #{e.message}" }
        end

        def ticket_times_hash(metadata, credential)
          explicit_times = metadata[:ticket_times]
          return explicit_times if explicit_times
          return nil if credential.nil?

          compact_hash(
            'auth_time' => credential.authtime,
            'start_time' => credential.starttime,
            'end_time' => credential.endtime,
            'renew_till' => credential.renew_till
          )
        end

        def encryption_key_summary(key, redact_binary: !full_trace?)
          return nil if key.nil?

          compact_hash(
            'type' => format_encryption_type(key.type),
            'value' => redact_binary ? binary_summary(key.value, redact_binary: true) : format_key_material(key.value)
          )
        end

        def binary_summary(value, redact_binary: !full_trace?)
          value = @token_parser.binary_string(value)
          return nil if value.nil?
          return value unless value.is_a?(String)
          return "[binary #{value.bytesize} bytes]" if redact_binary

          "[binary #{value.bytesize} bytes: #{value.unpack1('H*')}]"
        end

        def encoded_length(element)
          return nil if element.nil?

          element.encode.bytesize
        rescue StandardError
          nil
        end

        def format_message_type_value(msg_type)
          return nil if msg_type.nil?

          "#{msg_type} (#{@serializer.message_type_name(msg_type)})"
        end

        def format_ap_options(options)
          return nil if options.nil?

          flags = []
          flags << 'AP_USE_SESSION_KEY' if (options & 0x40000000) != 0
          flags << 'AP_MUTUAL_REQUIRED' if (options & 0x20000000) != 0
          "0x#{options.to_i.to_s(16).rjust(8, '0')} (#{flags.join(', ')})"
        end

        def principal_with_realm(principal, realm)
          name = principal_to_s(principal)
          return nil if name.nil?

          realm ? "#{name}@#{realm}" : name
        end

        def principal_to_s(principal)
          return nil if principal.nil?

          principal.to_s
        end

        def compact_nested_hash(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, entry), output|
              compacted = compact_nested_hash(entry)
              next if compacted.nil?
              next if compacted.respond_to?(:empty?) && compacted.empty?

              output[key] = compacted
            end
          when Array
            value.map { |entry| compact_nested_hash(entry) }.compact
          else
            value
          end
        end

        def serialize_trace_value(value, redact_binary:)
          case value
          when Hash
            value.each_with_object({}) do |(key, entry), output|
              output[key.to_s] = serialize_trace_value(entry, redact_binary: redact_binary)
            end
          when Array
            value.map { |entry| serialize_trace_value(entry, redact_binary: redact_binary) }
          else
            @serializer.serialize_value(value, redact_binary: redact_binary)
          end
        end

        def compact_hash(hash)
          hash.compact
        end

        def format_flags(flags)
          return nil if flags.nil?

          flags_value = flags.to_i
          flag_names = if flags.respond_to?(:enabled_flag_names)
                         flags.enabled_flag_names
                       else
                         Rex::Proto::Kerberos::Model::TicketFlags.new(flags_value).enabled_flag_names
                       end
          "0x#{flags_value.to_s(16).rjust(8, '0')} (#{flag_names.join(', ')})"
        end

        def format_encryption_type(encryption_type)
          return nil if encryption_type.nil?

          "#{encryption_type} (#{@serializer.encryption_type_name(encryption_type)})"
        end

        def format_key_material(key_material)
          return nil if blank_value?(key_material)

          key_material.unpack1('H*')
        end

        def blank_value?(value)
          return true if value.nil? || value == false
          return value.strip.empty? if value.respond_to?(:strip)
          return value.empty? if value.respond_to?(:empty?)

          false
        end
      end
    end
  end
end
