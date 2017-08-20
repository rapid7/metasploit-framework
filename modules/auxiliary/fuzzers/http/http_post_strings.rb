require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => "HTTP POST Fuzzer",
      'Description'    => %q{
        This module will fuzz a http server by sending a string generated from the options set as HTTP POST data
      },
      'Author'         => [ 'Aamir Mir <aamir[at]aamir.info>' ],
      'License'        => MSF_LICENSE
      ))
    register_options([
      Opt::RPORT(80),
      OptInt.new("LENGTH", [true, "The length of the string being sent", 10]),
      OptString.new("HEADER", [true, "HTTP Header to Fuzz, Options: none, content-type, user-agent, referer, auth, host, cookie","none"]),
      OptString.new("CHAR", [true, "The character used to build the string", "A"]),
      OptBool.new("PATTERN", [true, "If true the string will be created using msf pattern create rather than the value of CHAR","false"]),
    ], self.class)
  end

def run
  head = "POST / HTTP/1.0\r\n"
  char = datastore['CHAR']
  header = datastore['HEADER']
  len = datastore['LENGTH'].to_i

  if header == "none"
    bad_head = "\r\n"
  elsif header == "user-agent"
    bad_head = "User-Agent: "
  elsif header == "content-type"
    bad_head = "Content-Type: "
  elsif header == "referer"
    bad_head = "Referer: "
  elsif header == "auth"
    bad_head = "Authorization: Basic "
  elsif header == "host"
    bad_head = "Host: "
  elsif header == "cookie"
    bad_head = "Cookie: "
  else
    abort("Header is not a valid option")
  end

  if datastore['PATTERN']
    bad = Rex::Text.pattern_create(len)
  else
    bad = char * len
  end

  foot = "\r\n\r\n"

  final_bad = head + bad_head + bad + foot
  print_status("The fuzz string being sent is: ")
  print_status(final_bad.dump)
  connect
  sock.put(final_bad)
  sock.get_once(timeout = 5)
  disconnect
 end
end
