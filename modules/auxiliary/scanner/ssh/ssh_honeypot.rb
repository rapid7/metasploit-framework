##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh/transport/session'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Module::Deprecated
  moved_from 'auxiliary/scanner/ssh/detect_kippo'

  # When KEX algorithms were added to the default KEX list (for OpenSSH), with their minimum SSH version
  # This isn't when support was first added, nor when promoted to first default value, but added to default KEX list
  # Example. sntrup761x25519 : added in v8.5, a part of default in v8.9, first default value in v9.0
  COWRIE_KEX_CHECKS = [
    ['6.5', 'curve25519-sha256@libssh.org'],       # OpenSSH >= v6.5 ~ https://www.openssh.org/txt/release-6.5
    ['7.3', 'diffie-hellman-group14-sha256'],      # OpenSSH >= v7.3 ~ https://www.openssh.org/txt/release-7.3
    ['7.3', 'diffie-hellman-group16-sha512'],      # OpenSSH >= v7.3 ~ https://www.openssh.org/txt/release-7.3
    ['7.3', 'diffie-hellman-group18-sha512'],      # OpenSSH >= v7.3 ~ https://www.openssh.org/txt/release-7.3
    ['7.4', 'curve25519-sha256'],                  # OpenSSH >= v7.4 ~ https://www.openssh.org/txt/release-7.4
    ['8.9', 'sntrup761x25519-sha512@openssh.com'], # OpenSSH >= v8.9 ~ https://www.openssh.org/txt/release-8.9 (first added to default KEX) // OpenSSH >= v9.0 https://www.openssh.org/pq.html (Made as default)
    ['9.9', 'mlkem768x25519-sha256']               # OpenSSH >= v9.9 ~ https://www.openssh.org/txt/release-9.9 // OpenSSH >= v9.9 https://www.openssh.org/pq.html
  ].freeze

  # KEX algorithms never in OpenSSH's default at any version
  COWRIE_KEX_PHANTOM = [
    'sntrup4591761x25519-sha512@tinyssh.org' # Added in v8.0, removed in v8.5
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SSH Honeypot Detector (Kippo/Cowrie)',
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
      OptInt.new('TIMEOUT', [true, 'Timeout for the SSH probe', 30]),
      OptBool.new('EXTENDED_CHECKS', [true, 'Attempt to check the expected OS via the SSH banner', true])
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

  def report_honeypot_detected(banner, reason, honeypot:, confidence: 'likely')
    print_good("SSH honeypot detected: #{honeypot} (#{confidence}) - #{reason}")
    report_ssh_service(info: "SSH honeypot: #{honeypot} (#{banner.strip})")
    report_ssh_vuln(info: "SSH honeypot: #{honeypot} - #{reason}")
  end

  def run_host(_ip)
    connect
    banner = sock.get_once || ''
    sock.put(banner + "\n" * 8)
    response = sock.get_once || ''

    print_status("SSH banner: #{banner.strip}")
    report_ssh_host(banner) if datastore['EXTENDED_CHECKS']

    return if check_kippo(banner, response)
    return if check_cowrie(banner)

    print_status('No SSH honeypot (Kippo/Cowrie) detected')
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

    reason = 'Server gave incorrect response when probed'
    report_honeypot_detected(banner, reason, honeypot: 'Kippo', confidence: 'highly likely')
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

    server_kex = ::Timeout.timeout(timeout) do
      transport = Net::SSH::Transport::Session.new(rhost, port: rport)
      begin
        kex = transport.algorithms.instance_variable_get(:@server_data)[:kex].map(&:downcase)
        begin
          report_ssh_hostkeys(transport, rhost, rport)
        rescue StandardError
          nil
        end
        kex
      ensure
        begin
          transport.close
        rescue StandardError
          nil
        end
      end
    end

    vprint_status("SSH KEX algorithms: #{server_kex.join(', ')}")

    phantom = COWRIE_KEX_PHANTOM.select { |k| server_kex.include?(k) }
    if phantom.any?
      reason = "Advertises KEX never in OpenSSH default: #{phantom.join(', ')}"
      report_honeypot_detected(banner, reason, honeypot: 'Cowrie', confidence: 'possible')
      return true
    end

    if required_kex.empty?
      vprint_status("Not thought to be Cowrie - OpenSSH #{banner_ver} predates tracked KEX milestones")
      return false
    end

    missing = required_kex.reject { |k| server_kex.include?(k) }
    if missing.empty?
      vprint_status('Not thought to be Cowrie - Every expected KEX is present')
      return false
    end

    reason = "Claims OpenSSH #{banner_ver} but missing expected KEX: #{missing.join(', ')}"
    report_honeypot_detected(banner, reason, honeypot: 'Cowrie')
    true
  rescue Rex::ConnectionError, Net::SSH::Exception, Timeout::Error => e
    print_error("Cowrie check error: #{e.message}")
    false
  end
end
