##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Gopher gophermap Scanner',
      'Description' => %q(
        This module identifies Gopher servers, and processes the gophermap
        file which lists all the files on the server.
      ),
      'References'  =>
        [
          ['URL', 'https://sdfeu.org/w/tutorials:gopher']
        ],
      'Author'      => 'h00die',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(70),
        OptString.new('PATH', [false, 'Path to enumerate', ''])
      ]
    )
  end

  TYPE_MAP = {
    '0' => 'Text file',
    '1' => 'Directory',
    '2' => 'CSO name server',
    '3' => 'Error',
    '4' => 'Mac HQX filer',
    '5' => 'PC binary',
    '6' => 'UNIX uuencoded file',
    '7' => 'Search server',
    '8' => 'Telnet Session',
    '9' => 'Binary File',
    'c' => 'Calendar',
    'e' => 'Event',
    'g' => 'GIF image',
    'h' => 'HTML',
    'i' => 'inline text',
    's' => 'Sound',
    'I' => 'Image',
    'M' => 'MIME multipart/mixed message',
    'T' => 'TN3270 Session'
  }.freeze

  def get_type(char)
    TYPE_MAP.fetch(char.chomp)
  end

  def run_host(ip)
    begin
      connect
      sock.put("#{datastore['path']}\r\n")
      gophermap = sock.get_once
      if gophermap
        gophermap.split("\r\n").each do |line|
          line_parts = line.split("\t")
          next unless line_parts.length >= 2
          # syntax: [type_character]description[tab]path[tab, after this is optional]server[tab]port
          line_parts = line.split("\t")
          desc = line_parts[0]
          type_char = desc.slice!(0) # remove first character which is the file type
          file_type = get_type(type_char)
          if file_type && file_type == 'inline text'
            print_good(desc)
            next
          end
          if file_type
            print_good("  #{file_type}: #{desc}")
          else
            print_good("  Invalid File Type (#{type_char}): #{desc}")
          end
          if line_parts.length >= 3
            print_good("    Path: #{line_parts[2]}:#{line_parts[3]}#{line_parts[1]}")
          elsif line.length >= 2
            print_good("    Path: #{line_parts[2]}#{line_parts[1]}")
          else
            print_good("    Path: #{line_parts[1]}")

          end
        end
        report_service(host: ip, port: rport, service: 'gopher', info: gophermap)
      else
        print_error('No gophermap')
      end
    rescue ::Rex::ConnectionError, ::IOError, ::Errno::ECONNRESET
    rescue ::Exception => e
      print_error("#{ip}: #{e} #{e.backtrace}")
    ensure
      disconnect
    end
  end
end
