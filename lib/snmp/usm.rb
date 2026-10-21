# frozen_string_literal: true

require 'openssl'
require 'snmp/pdu'

module SNMP
  class SecurityError < RuntimeError; end
  class InvalidSecurityParameters < SecurityError; end
  class AuthenticationError < SecurityError; end
  class DecryptionError < SecurityError; end

  # Represents an SNMPv3 Report PDU.
  class Report < PDU
    # @return [String] BER-encoded Report PDU
    def encode
      encode_pdu(Report_PDU_TAG)
    end
  end

  # Holds decoded SNMPv3 message metadata and its scoped PDU.
  class V3Message
    attr_reader :message_id, :security_flags, :engine_id, :engine_boots, :engine_time, :pdu

    # @param message_id [Integer] SNMPv3 message identifier
    # @param security_flags [Integer] decoded SNMPv3 message flags
    # @param engine_id [String] authoritative SNMP engine ID
    # @param engine_boots [Integer] authoritative engine boot counter
    # @param engine_time [Integer] authoritative engine time
    # @param pdu [PDU] decoded scoped PDU
    def initialize(message_id:, security_flags:, engine_id:, engine_boots:, engine_time:, pdu:)
      @message_id = message_id
      @security_flags = security_flags
      @engine_id = engine_id
      @engine_boots = engine_boots
      @engine_time = engine_time
      @pdu = pdu
    end

    # @return [Boolean] whether the message has authentication enabled
    def authenticated?
      (security_flags & 0x01) == 0x01
    end

    # @return [Boolean] whether the scoped PDU is encrypted
    def encrypted?
      (security_flags & 0x02) == 0x02
    end

    # @return [Boolean] whether the scoped PDU is a Report PDU
    def report?
      pdu.is_a?(Report)
    end
  end

  # Implements the User-based Security Model used by SNMPv3 command
  # generators. See RFCs 3414, 3826, and 7860.
  class UserBasedSecurityModel
    include BER

    AUTH_PROTOCOLS = {
      'MD5' => { digest: 'MD5', mac_length: 12 },
      'SHA1' => { digest: 'SHA1', mac_length: 12 },
      'SHA224' => { digest: 'SHA224', mac_length: 16 },
      'SHA256' => { digest: 'SHA256', mac_length: 24 },
      'SHA384' => { digest: 'SHA384', mac_length: 32 },
      'SHA512' => { digest: 'SHA512', mac_length: 48 }
    }.freeze

    SECURITY_LEVEL_FLAGS = {
      'noAuthNoPriv' => 0x00,
      'authNoPriv' => 0x01,
      'authPriv' => 0x03
    }.freeze

    REPORT_OIDS = {
      '1.3.6.1.6.3.15.1.1.1.0' => 'unsupported security level',
      '1.3.6.1.6.3.15.1.1.2.0' => 'not in time window',
      '1.3.6.1.6.3.15.1.1.3.0' => 'unknown username',
      '1.3.6.1.6.3.15.1.1.4.0' => 'unknown engine ID',
      '1.3.6.1.6.3.15.1.1.5.0' => 'wrong authentication digest',
      '1.3.6.1.6.3.15.1.1.6.0' => 'decryption error'
    }.freeze

    ENGINE_DISCOVERY_OID = '1.3.6.1.6.3.15.1.1.4.0'

    # @param username [String] SNMPv3 USM username
    # @param security_level [String] noAuthNoPriv, authNoPriv, or authPriv
    # @param auth_protocol [String] MD5, SHA1, SHA224, SHA256, SHA384, or SHA512
    # @param auth_password [String] authentication passphrase
    # @param priv_protocol [String] AES or AES128
    # @param priv_password [String] privacy passphrase
    # @param context_name [String] SNMP context name
    def initialize(username:, security_level:, auth_protocol:, auth_password:, priv_protocol:, priv_password:, context_name: '')
      @username = username.to_s.b
      @security_level = security_level.to_s
      @auth_protocol = auth_protocol.to_s.upcase.delete('-')
      @auth_password = auth_password.to_s.b
      @priv_protocol = priv_protocol.to_s.upcase.delete('-')
      @priv_password = priv_password.to_s.b
      @context_name = context_name.to_s.b
      @salt = rand(0...(2**64))

      validate_configuration!
    end

    # @return [Boolean] whether authoritative engine state is available
    def engine_known?
      !@engine_id.nil?
    end

    # Clears authoritative engine state and localized keys.
    # @return [void]
    def forget_engine
      @engine_id = nil
      @engine_boots = nil
      @engine_time = nil
      @synchronized_at = nil
      @auth_key = nil
      @priv_key = nil
    end

    # Encodes an unauthenticated engine-discovery request.
    # @param request [PDU] request PDU
    # @param message_id [Integer] SNMPv3 message identifier
    # @param max_size [Integer] maximum response message size
    # @return [String] BER-encoded SNMPv3 message
    def discovery_message(request, message_id, max_size)
      security = {
        flags: 0x04,
        engine_id: String.new(encoding: Encoding::BINARY),
        engine_boots: 0,
        engine_time: 0,
        username: String.new(encoding: Encoding::BINARY),
        auth_parameters: String.new(encoding: Encoding::BINARY),
        priv_parameters: String.new(encoding: Encoding::BINARY)
      }
      packet, = encode_message(
        message_id: message_id,
        max_size: max_size,
        security: security,
        scoped_data: scoped_pdu(request, String.new(encoding: Encoding::BINARY))
      )
      packet
    end

    # Decodes a matching engine-discovery Report and records engine state.
    # @param packet [String] BER-encoded SNMPv3 response
    # @param expected_message_id [Integer, nil] expected message identifier
    # @param expected_request_id [Integer, nil] expected request identifier
    # @return [V3Message, nil] decoded message, or nil for an unrelated response
    def process_discovery_response(packet, expected_message_id: nil, expected_request_id: nil)
      message = decode_message(packet)
      return nil if expected_message_id && message.message_id != expected_message_id
      return nil if expected_request_id && message.pdu.request_id != expected_request_id

      unless message.report?
        raise InvalidSecurityParameters, 'SNMPv3 discovery requires a Report PDU'
      end

      varbinds = message.pdu.varbind_list
      unless varbinds.length == 1 &&
             varbinds.first.name.to_s == ENGINE_DISCOVERY_OID
        raise InvalidSecurityParameters, 'SNMPv3 discovery requires an unknown-engine Report'
      end

      unless varbinds.first.value.is_a?(Counter32)
        raise InvalidSecurityParameters, 'SNMPv3 discovery Report must contain a Counter32 value'
      end

      unless message.engine_id.bytesize.between?(5, 32)
        raise InvalidSecurityParameters, 'SNMPv3 discovery engine ID must contain 5 through 32 bytes'
      end

      unless message.engine_boots.between?(0, 2_147_483_646)
        raise InvalidSecurityParameters, 'SNMPv3 discovery contains an invalid engine boot counter'
      end

      unless message.engine_time.between?(0, 2_147_483_647)
        raise InvalidSecurityParameters, 'SNMPv3 discovery contains an invalid engine time'
      end

      synchronize_engine(message.engine_id, message.engine_boots, message.engine_time)
      message
    end

    # Encodes an authenticated and optionally encrypted request.
    # @param request [PDU] request PDU
    # @param message_id [Integer] SNMPv3 message identifier
    # @param max_size [Integer] maximum response message size
    # @return [String] BER-encoded SNMPv3 message
    def request_message(request, message_id, max_size)
      raise InvalidSecurityParameters, 'SNMPv3 authoritative engine is unknown' unless engine_known?

      security_flags = SECURITY_LEVEL_FLAGS.fetch(@security_level) | 0x04
      engine_time = current_engine_time
      plaintext = scoped_pdu(request, @engine_id)
      priv_parameters = String.new(encoding: Encoding::BINARY)
      scoped_data = plaintext

      if privacy?
        priv_parameters = next_salt
        scoped_data = encode_octet_string(encrypt(plaintext, @engine_boots, engine_time, priv_parameters))
      end

      auth_parameters = authentication? ? "\x00".b * authentication_parameters_length : String.new(encoding: Encoding::BINARY)
      security = {
        flags: security_flags,
        engine_id: @engine_id,
        engine_boots: @engine_boots,
        engine_time: engine_time,
        username: @username,
        auth_parameters: auth_parameters,
        priv_parameters: priv_parameters
      }
      packet, auth_offset = encode_message(
        message_id: message_id,
        max_size: max_size,
        security: security,
        scoped_data: scoped_data
      )
      return packet unless authentication?

      mac = authentication_code(packet)
      packet[auth_offset, mac.bytesize] = mac
      packet
    end

    # Authenticates, decrypts, and processes a matching response.
    # @param packet [String] BER-encoded SNMPv3 response
    # @param expected_message_id [Integer, nil] expected message identifier
    # @param expected_request_id [Integer, nil] expected request identifier
    # @return [V3Message, nil] decoded message, or nil for an unrelated response
    def process_response(packet, expected_message_id: nil, expected_request_id: nil)
      message = decode_message(packet)
      return nil if expected_message_id && message.message_id != expected_message_id
      return nil if expected_request_id && message.pdu.request_id != expected_request_id

      if !message.authenticated? && !message.report? && authentication?
        raise AuthenticationError, 'SNMPv3 response did not use authentication'
      end

      if !message.report? && privacy? && !message.encrypted?
        raise DecryptionError, 'SNMPv3 response did not use privacy'
      end

      return message unless message.authenticated?

      if engine_known?
        unless message.engine_id == @engine_id
          raise AuthenticationError, 'SNMPv3 response engine ID does not match the discovered engine'
        end

        if message.engine_boots.negative? || message.engine_boots >= 2_147_483_647
          raise AuthenticationError, 'SNMPv3 response contains an invalid engine boot counter'
        end

        if message.engine_time.negative? || message.engine_time > 2_147_483_647
          raise AuthenticationError, 'SNMPv3 response contains an invalid engine time'
        end

        if message.engine_boots < @engine_boots
          raise AuthenticationError, 'SNMPv3 response contains an older engine boot counter'
        end

        if message.engine_boots == @engine_boots &&
           message.engine_time < current_engine_time - 150
          raise AuthenticationError, 'SNMPv3 response is outside the engine time window'
        end

        # Accept in-window reordered responses without moving cached state backward.
        if message.engine_boots == @engine_boots &&
           message.engine_time <= @engine_time
          return message
        end
      end

      synchronize_engine(message.engine_id, message.engine_boots, message.engine_time)
      message
    end

    # Returns the standardized description for a Report PDU.
    # @param report [PDU] decoded Report PDU
    # @return [String] report description
    def report_description(report)
      oid = report.varbind_list.first&.name&.to_s
      REPORT_OIDS.fetch(oid, "unknown report #{oid || '(empty)'}")
    end

    # @param report [PDU] decoded Report PDU
    # @return [Boolean] whether rediscovery may recover the request
    def resynchronization_report?(report)
      oid = report.varbind_list.first&.name&.to_s
      oid == '1.3.6.1.6.3.15.1.1.2.0' || oid == ENGINE_DISCOVERY_OID
    end

    private

    def validate_configuration!
      unless SECURITY_LEVEL_FLAGS.key?(@security_level)
        raise InvalidSecurityParameters, "Unsupported SNMPv3 security level #{@security_level.inspect}"
      end

      raise InvalidSecurityParameters, 'SNMPv3 username is required' if @username.empty?
      return unless authentication?

      raise InvalidSecurityParameters, "Unsupported SNMPv3 authentication protocol #{@auth_protocol.inspect}" unless AUTH_PROTOCOLS.key?(@auth_protocol)
      raise InvalidSecurityParameters, 'SNMPv3 authentication passphrase must contain at least 8 bytes' if @auth_password.bytesize < 8
      return unless privacy?

      raise InvalidSecurityParameters, "Unsupported SNMPv3 privacy protocol #{@priv_protocol.inspect}" unless %w[AES AES128].include?(@priv_protocol)
      raise InvalidSecurityParameters, 'SNMPv3 privacy passphrase must contain at least 8 bytes' if @priv_password.bytesize < 8
    end

    def authentication?
      SECURITY_LEVEL_FLAGS.fetch(@security_level) & 0x01 == 0x01
    end

    def privacy?
      SECURITY_LEVEL_FLAGS.fetch(@security_level) & 0x02 == 0x02
    end

    def authentication_parameters
      AUTH_PROTOCOLS.fetch(@auth_protocol)
    end

    def authentication_parameters_length
      authentication_parameters.fetch(:mac_length)
    end

    def password_to_key(password)
      repetitions = (1_048_576 / password.bytesize) + 1
      material = (password * repetitions).byteslice(0, 1_048_576)
      OpenSSL::Digest.digest(authentication_parameters.fetch(:digest), material)
    end

    def localize_key(password, engine_id)
      key = password_to_key(password)
      OpenSSL::Digest.digest(authentication_parameters.fetch(:digest), key + engine_id + key)
    end

    def synchronize_engine(engine_id, engine_boots, engine_time)
      changed = @engine_id != engine_id
      @engine_id = engine_id.b
      @engine_boots = engine_boots
      @engine_time = engine_time
      @synchronized_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      return unless changed || @auth_key.nil?

      @auth_key = localize_key(@auth_password, @engine_id) if authentication?
      @priv_key = localize_key(@priv_password, @engine_id) if privacy?
    end

    def current_engine_time
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - @synchronized_at
      @engine_time + elapsed.to_i
    end

    def next_salt
      @salt = (@salt + 1) % (2**64)
      [@salt >> 32, @salt & 0xffffffff].pack('NN')
    end

    def encrypt(plaintext, engine_boots, engine_time, salt)
      cipher = OpenSSL::Cipher.new('aes-128-cfb').encrypt
      cipher.padding = 0
      cipher.key = @priv_key.byteslice(0, 16)
      cipher.iv = [engine_boots, engine_time].pack('NN') + salt
      cipher.update(plaintext) + cipher.final
    end

    def decrypt(ciphertext, engine_boots, engine_time, salt)
      raise DecryptionError, 'SNMPv3 privacy parameters must contain an 8-byte AES salt' unless salt.bytesize == 8

      cipher = OpenSSL::Cipher.new('aes-128-cfb').decrypt
      cipher.padding = 0
      cipher.key = @priv_key.byteslice(0, 16)
      cipher.iv = [engine_boots, engine_time].pack('NN') + salt
      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError => e
      raise DecryptionError, "Unable to decrypt SNMPv3 scoped PDU: #{e.message}"
    end

    def authentication_code(packet)
      OpenSSL::HMAC.digest(authentication_parameters.fetch(:digest), @auth_key, packet).byteslice(0, authentication_parameters_length)
    end

    def scoped_pdu(request, context_engine_id)
      encode_sequence(encode_octet_string(context_engine_id) + encode_octet_string(@context_name) + request.encode)
    end

    def encode_message(message_id:, max_size:, security:, scoped_data:)
      header = encode_sequence(
        encode_integer(message_id) +
        encode_integer(max_size) +
        encode_octet_string(security.fetch(:flags).chr.b) +
        encode_integer(3)
      )

      security_prefix =
        encode_octet_string(security.fetch(:engine_id)) +
        encode_integer(security.fetch(:engine_boots)) +
        encode_integer(security.fetch(:engine_time)) +
        encode_octet_string(security.fetch(:username))
      auth_field = encode_octet_string(security.fetch(:auth_parameters))
      security_body = security_prefix + auth_field + encode_octet_string(security.fetch(:priv_parameters))
      security_sequence = encode_sequence(security_body)
      security_field = encode_octet_string(security_sequence)
      version = encode_integer(SNMP_V3)
      message_body = version + header + security_field + scoped_data
      packet = encode_sequence(message_body)

      auth_offset =
        (packet.bytesize - message_body.bytesize) +
        version.bytesize +
        header.bytesize +
        (security_field.bytesize - security_sequence.bytesize) +
        (security_sequence.bytesize - security_body.bytesize) +
        security_prefix.bytesize +
        (auth_field.bytesize - security.fetch(:auth_parameters).bytesize)
      [packet, auth_offset]
    end

    def decode_message(packet)
      message_body, remainder, outer_header = consume(packet, SEQUENCE_TAG)
      assert_no_remainder(remainder)

      version_value, message_remainder, = consume(message_body, INTEGER_TAG)
      raise UnsupportedVersion, decode_integer_value(version_value).to_s unless decode_integer_value(version_value) == SNMP_V3

      version_length = message_body.bytesize - message_remainder.bytesize
      header_body, after_header, = consume(message_remainder, SEQUENCE_TAG)
      header_length = message_remainder.bytesize - after_header.bytesize
      message_id, header_remainder = consume_integer(header_body)
      _max_size, header_remainder = consume_integer(header_remainder)
      flags, header_remainder, = consume(header_remainder, OCTET_STRING_TAG)
      security_model, header_remainder = consume_integer(header_remainder)
      assert_no_remainder(header_remainder)
      raise InvalidSecurityParameters, "Unsupported SNMPv3 security model #{security_model}" unless security_model == 3
      raise InvalidSecurityParameters, 'SNMPv3 security flags must contain exactly one byte' unless flags.bytesize == 1

      security_sequence, scoped_data, security_field_header = consume(after_header, OCTET_STRING_TAG)
      security_body, security_remainder, = consume(security_sequence, SEQUENCE_TAG)
      assert_no_remainder(security_remainder)

      engine_id, security_body = consume_octet_string(security_body)
      engine_boots, security_body = consume_integer(security_body)
      engine_time, security_body = consume_integer(security_body)
      username, security_body = consume_octet_string(security_body)
      auth_field_input = security_body
      auth_parameters, security_body, auth_field_header = consume(auth_field_input, OCTET_STRING_TAG)
      priv_parameters, security_body = consume_octet_string(security_body)
      assert_no_remainder(security_body)

      auth_offset =
        outer_header +
        version_length +
        header_length +
        security_field_header +
        (security_sequence.bytesize - auth_field_input.bytesize) +
        auth_field_header

      security_flags = flags.getbyte(0)
      if security_flags & 0x01 == 0x01
        raise AuthenticationError, 'SNMPv3 authentication is not configured' unless authentication?
        raise AuthenticationError, "Unexpected SNMPv3 authentication parameter length #{auth_parameters.bytesize}" unless auth_parameters.bytesize == authentication_parameters_length

        authenticated_packet = packet.dup
        authenticated_packet[auth_offset, auth_parameters.bytesize] = "\x00".b * auth_parameters.bytesize
        expected = authentication_code(authenticated_packet)
        raise AuthenticationError, 'SNMPv3 response authentication failed' unless expected == auth_parameters
      end

      scoped_body_tag, scoped_body, scoped_remainder, = consume_tagged(scoped_data)
      assert_no_remainder(scoped_remainder)
      plaintext = if security_flags & 0x02 == 0x02
                    raise DecryptionError, 'SNMPv3 encrypted response was not authenticated' if security_flags & 0x01 != 0x01
                    raise DecryptionError, 'SNMPv3 privacy is not configured' unless privacy?
                    raise InvalidSecurityParameters, "Unexpected encrypted scoped PDU tag #{scoped_body_tag}" unless scoped_body_tag == OCTET_STRING_TAG

                    decrypt(scoped_body, engine_boots, engine_time, priv_parameters)
                  else
                    raise InvalidSecurityParameters, "Unexpected plaintext scoped PDU tag #{scoped_body_tag}" unless scoped_body_tag == SEQUENCE_TAG

                    encode_sequence(scoped_body)
                  end

      pdu = decode_scoped_pdu(plaintext)

      if pdu.is_a?(Response) && username != @username
        raise InvalidSecurityParameters, 'SNMPv3 response username does not match the configured user'
      end

      V3Message.new(
        message_id: message_id,
        security_flags: security_flags,
        engine_id: engine_id,
        engine_boots: engine_boots,
        engine_time: engine_time,
        pdu: pdu
      )
    rescue OutOfData, InvalidLength, InvalidTag => e
      raise ParseError, "Malformed SNMPv3 message: #{e.message}"
    end

    def decode_scoped_pdu(data)
      scoped_body, scoped_remainder, = consume(data, SEQUENCE_TAG)
      assert_no_remainder(scoped_remainder)
      context_engine_id, scoped_body = consume_octet_string(scoped_body)
      context_name, scoped_body = consume_octet_string(scoped_body)
      tag, pdu_body, scoped_remainder, = consume_tagged(scoped_body)
      assert_no_remainder(scoped_remainder)

      pdu_class = {
        GetRequest_PDU_TAG => GetRequest,
        GetNextRequest_PDU_TAG => GetNextRequest,
        Response_PDU_TAG => Response,
        SetRequest_PDU_TAG => SetRequest,
        GetBulkRequest_PDU_TAG => GetBulkRequest,
        InformRequest_PDU_TAG => InformRequest,
        SNMPv2_Trap_PDU_TAG => SNMPv2_Trap,
        Report_PDU_TAG => Report
      }.fetch(tag) { raise UnsupportedPduTag, tag.to_s }

      pdu = PDU.decode(pdu_class, pdu_body)

      if pdu.is_a?(Response)
        # Requests currently use the discovered authoritative engine as
        # their scoped context engine; responses must match that context.
        unless context_engine_id == @engine_id
          raise InvalidSecurityParameters, 'SNMPv3 response context engine ID does not match the requested context'
        end

        unless context_name == @context_name
          raise InvalidSecurityParameters, 'SNMPv3 response context name does not match the requested context'
        end
      end

      pdu
    end

    def consume(data, expected_tag)
      tag, value, remainder = decode_tlv(data)
      raise InvalidTag, tag.to_s unless tag == expected_tag

      consumed = data.bytesize - remainder.bytesize
      [value, remainder, consumed - value.bytesize]
    end

    def consume_tagged(data)
      tag, value, remainder = decode_tlv(data)
      consumed = data.bytesize - remainder.bytesize
      [tag, value, remainder, consumed - value.bytesize]
    end

    def consume_integer(data)
      value, remainder, = consume(data, INTEGER_TAG)
      [decode_integer_value(value), remainder]
    end

    def consume_octet_string(data)
      value, remainder, = consume(data, OCTET_STRING_TAG)
      [value, remainder]
    end
  end
end
