##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh/transport/session'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Module::Deprecated
  moved_from 'auxiliary/scanner/ssh/detect_kippo'

  # KEX algorithms required for a given minimum SSH version
  COWRIE_KEX_CHECKS = [
    # [min_ver, required_kex]
    ['9.0', 'sntrup761x25519-sha512@openssh.com'], # OpenSSH >= 9.0 ~ https://www.openssh.org/pq.html
    ['9.9', 'mlkem768x25519-sha256']               # OpenSSH >= 9.9 ~ https://www.openssh.org/pq.html
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SSH Honeypot Detector (Cowrie/Kippo)',
        'Description' => %q{
          This module will attempt to detect if an SSH service is a SSH honeypot,
          such as Kippo or Cowrie, pre-authentication.

          Kippo detection is done by issuing unexpected data to the SSH service
          pre-authentication and checking the response for two particular
          non-standard error messages.

          Cowrie detection happens by checking for mismatches between OpenSSH version
          via the banner and the KEX algorithms advertised in SSH_MSG_KEXINIT.
        },
        'Author' => [
          'Andrew Morris <andrew[at]morris.guru>',
          'g0tmi1k' # @g0tmi1k - additional features
        ],
        'References' => [
          ['URL', 'https://www.obscurechannel.com/x42/magicknumber.html'],
          ['URL', 'https://web.archive.org/web/20170904010325/https://morris.sc/detecting-kippo-ssh-honeypots/']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(22),
      OptInt.new('TIMEOUT', [true, 'Timeout for the SSH probe', 30])
    ])
  end

  def timeout
    datastore['TIMEOUT']
  end

  def report_ssh_service(info: nil)
    report_service(
      host: rhost,
      port: rport,
      name: 'ssh',
      proto: 'tcp',
      info: info.to_s.strip
    )
  end

  def report_ssh_vuln(info: nil)
    report_vuln(
      host: rhost,
      port: rport,
      proto: 'tcp',
      sname: 'ssh',
      name: 'SSH Honeypot Detected',
      info: info.to_s.strip,
      refs: references
    )
  end

  def run_host(_ip)
    connect
    banner = sock.get_once || ''
    sock.put(banner + "\n" * 8)
    response = sock.get_once || ''

    print_status("SSH banner: #{banner.strip}")

    return if check_kippo(banner, response)
    return if check_cowrie(banner)

    print_status('No SSH honeypot detected')
    report_ssh_service(info: banner)
  rescue Rex::ConnectionError
    print_error('Connection refused or timed out')
  ensure
    disconnect
  end

  def check_kippo(banner, response)
    unless response =~ /(?:^Protocol mismatch\.\n$|bad packet length)/
      vprint_status('Not thought to be Kippo - Received expected SSH probe')
      return false
    end

    print_good("SSH honeypot detected: Kippo (highly likely)")
    report_ssh_service(info: "SSH honeypot: Kippo (#{banner.strip})")
    report_ssh_vuln(info: 'SSH honeypot: Kippo - Server gave incorrect response when probed')
    true
  end

  def check_cowrie(banner)
    banner_ssh_ver = banner.include?('_') ? banner.split('_').last.split('p').first : nil
    unless banner_ssh_ver
      vprint_status('Skipping Cowrie - No version found in banner')
      return false
    end

    banner_ver = Rex::Version.new(banner_ssh_ver)

    required_kex = COWRIE_KEX_CHECKS.filter_map do |min_ver, kex|
      kex if banner_ver >= Rex::Version.new(min_ver)
    end
    if required_kex.empty?
      vprint_status("Not thought to be Cowrie - OpenSSH #{banner_ver} predates post-quantum KEX")
      return false
    end

    server_kex = ::Timeout.timeout(timeout) do
      transport = Net::SSH::Transport::Session.new(rhost, port: rport)
      begin
        transport.algorithms.instance_variable_get(:@server_data)[:kex].map(&:downcase)
      ensure
        begin
          transport.close
        rescue StandardError
          nil
        end
      end
    end

    vprint_status("SSH KEX algorithms: #{server_kex.join(', ')}")

    missing = required_kex.reject { |k| server_kex.include?(k) }
    if missing.empty?
      vprint_status('Not thought to be Cowrie - Every KEX is expected')
      return false
    end

    reason = "Claims OpenSSH #{banner_ver} but missing expected KEX: #{missing.join(', ')}"
    print_good("SSH honeypot detected: Cowrie (likely) - #{reason}")
    report_ssh_service(info: "SSH honeypot: Cowrie (#{banner.strip})")
    report_ssh_vuln(info: "SSH honeypot: Cowrie - #{reason}")
    true
  rescue Rex::ConnectionError, Net::SSH::Exception, Timeout::Error => e
    print_error("Cowrie check error: #{e.message}")
    false
  end
end
