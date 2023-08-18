# -*- coding: binary -*-

require 'base64'
require 'openssl'
require 'net/imap/sasl'

# Namespace for Metasploit branch.
module Msf
module Db
module PostgresPR

# Implements SCRAM-SHA-256 authentication; The caller of #negotiate can additionally wrap the calculated authentication
# models with SASL/GSSAPI as appropriate
#
# https://datatracker.ietf.org/doc/html/rfc7677#section-3
class ScramSha256
  class NormalizeError < ArgumentError
  end

  # @param [String] user
  # @param [String] password
  def negotiate(user, password)
    random_nonce = b64(SecureRandom.bytes(32))

    # Attributes: https://datatracker.ietf.org/doc/html/rfc5802#section-5
    client_first_without_gs2_header = "n=#{normalize(user)},r=#{random_nonce}"
    client_gs2_header = gs2_header(channel_binding: false)
    client_first = "#{client_gs2_header}#{client_first_without_gs2_header}"

    server_first_string = yield :client_first, client_first

    server_first = parse_server_response(server_first_string)
    server_nonce = server_first[:r]
    server_salt = Base64.strict_decode64(server_first[:s])
    iterations = server_first[:i].to_i

    # https://datatracker.ietf.org/doc/html/rfc5802#section-3
    salted_password = hi(normalize(password), server_salt, iterations)
    client_key = hmac(salted_password, "Client Key")
    stored_key = h(client_key)

    client_final_without_proof = "c=#{b64(client_gs2_header)},r=#{server_nonce}"

    auth_message = [client_first_without_gs2_header, server_first_string, client_final_without_proof].join(',')
    client_signature = hmac(stored_key, auth_message)
    client_proof = xor_strings(client_key, client_signature)
    server_key = hmac(salted_password, "Server Key")
    expected_server_signature = hmac(server_key, auth_message)

    client_final = "#{client_final_without_proof},p=#{b64(client_proof)}"

    server_final = yield :client_final, client_final
    raise AuthenticationMethodMismatch, 'Server proof failed' if server_final != "v=#{b64(expected_server_signature)}"

    nil
  end

  # Implements Normalize from https://datatracker.ietf.org/doc/html/rfc4013 -
  # Apply the SASLprep profile [RFC4013] of the "stringprep" algorithm [RFC3454]
  #
  # @param [String] value
  # @return [String]
  def normalize(value)
    ::Net::IMAP::SASL.saslprep(value, exception: true)
  rescue ArgumentError => e
    raise NormalizeError, e.message
  end

  # Hi function implementation from
  # https://datatracker.ietf.org/doc/html/rfc5802#section-2.2
  #
  # @param [String] str
  # @param [String] salt
  # @param [Numeric] iteration_count
  def hi(str, salt, iteration_count)
    u = hmac(str, "#{salt.b}#{"\x00\x00\x00\x01".b}")
    u_i = u
    (iteration_count - 1).times do
      u_i = hmac(str, u_i)
      u = xor_strings(u, u_i)
    end

    u
  end

  # @return [String]
  def hash_function_name
    'SHA256'
  end

  # H function from
  # https://datatracker.ietf.org/doc/html/rfc5802#section-2.2
  #
  # @param [String] str
  def h(str)
    OpenSSL::Digest.digest(hash_function_name, str)
  end

  # @param [String] key
  # @param [String] message
  # @return [String]
  def hmac(key, message)
    OpenSSL::HMAC.digest(hash_function_name, key, message)
  end

  # Implements https://datatracker.ietf.org/doc/html/rfc5801#section-4
  # @return [String] The bytes for a gs2 header
  def gs2_header(channel_binding: false)
    # Specified as gs2-cb-flag
    if channel_binding
      # gs2_channel_binding_flag = 'y'
      # Implementation skipped for now, just haven't
      raise NotImplementedError, 'Channel binding not implemented'
    else
      gs2_channel_binding_flag = 'n'
    end

    gs2_authzid = nil
    gs2_header = "#{gs2_channel_binding_flag},#{gs2_authzid},"
    gs2_header
  end

  private

  # @param [String] value
  def b64(value)
    Base64.strict_encode64(value)
  end

  # @param [String] s1
  # @param [String] s2
  # @return [String] the strings XOR'd
  def xor_strings(s1, s2)
    s1.bytes.zip(s2.bytes).map { |(b1, b2)| b1 ^ b2 }.pack("C*")
  end

  # Parses a server response string such as 'r=2kRpTcHEFyoG+UgDEpRBdVcJLTWh5WtxARhYOHcG27i7YxAi,s=GNpgixWS5E4INbrMf665Kw==,i=4096'
  # into a Ruby hash equivalent { r: '2kRpT...', i: '4096' }
  # @param [String] string Server string response string
  def parse_server_response(string)
    string.split(',')
          .each_with_object({}) do |key_value, result|
      key, value = key_value.split('=', 2)
      result[key.to_sym] = value
    end
  end
end

end
end
end
