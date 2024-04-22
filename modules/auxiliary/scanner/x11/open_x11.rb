##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Auxiliary::Scanner
  include Auxiliary::Report
  include Exploit::Remote::X11

  def initialize
    super(
      'Name'	=> 'X11 No-Auth Scanner',
      'Description'	=> %q{
        This module scans for X11 servers that allow anyone
        to connect without authentication.
      },
      'Author'	=> [
        'tebo <tebodell[at]gmail.com>', # original module
        'h00die' # X11 library
      ],
      'References' => [
        ['OSVDB', '309'],
        ['CVE', '1999-0526'],
      ],
      'License'	=> MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => [],
        'RelatedModules' => [
          'auxiliary/gather/x11_keyboard_spy',
        ]
      }
    )

    register_options([
      Opt::RPORT(6000)
    ])
  end

  def run_host(ip)
    connect
    sock.put(X11ConnectionRequest.new.to_binary_s) # x11 session establish
    packet = ''
    connection = nil
    begin
      loop do
        new_data = sock.get_once(-1, 1)
        break if new_data.nil?

        packet += new_data
        begin
          connection = X11ConnectionResponse.read(packet)
          break # Break loop if packet is successfully read
        rescue EOFError
          vprint_bad("Connection packet malformed (size: #{packet.length}), attempting to read more data")
          # Continue looping to try and receive more data
        end
      end
    rescue StandardError => e
      vprint_bad("Error processing data: #{e}")
    end

    if connection.nil?
      vprint_bad('No connection, or bad X11 response received')
      return
    end

    begin
      if connection.success == 1
        print_connection_info(connection, ip, rport)
      else
        vprint_error("#{ip} Access Denied")
      end
    rescue StandardError
      vprint_bad('Failed to parse X11 connection initialization response packet')
    end

    disconnect
  rescue ::Rex::ConnectionError
  rescue ::Errno::EPIPE
  end
end
