##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Framework web site for more information on licensing and terms of use.
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Ruby on Rails JSON Processor YAML Deserialization Scanner',
      'Description' => %q{
        This module attempts to identify Ruby on Rails instances vulnerable to
        an arbitrary object instantiation flaw in the JSON request processor.
      },
      'Author'      =>
        [
            'jjarmoc',	# scanner module
            'hdm'		# CVE-2013-0156 scanner, basis of this technique.
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2013-0333']
        ]
    ))

    register_options([
      OptString.new('TARGETURI', [true, "The URI to test", "/"]),
      OptEnum.new('HTTP_METHOD', [true, 'HTTP Method', 'POST', ['GET', 'POST', 'PUT']]),
    ], self.class)
  end

  def send_probe(pdata)
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI']),
      'method' => datastore['HTTP_METHOD'],
      'ctype'  => 'application/json',
      'data'   => pdata
    })
  end

  def run_host(ip)

    # Straight JSON as a baseline
    res1 = send_probe(
      "{ \"#{Rex::Text.rand_text_alpha(rand(8)+1)}\" : \"#{Rex::Text.rand_text_alpha(rand(8)+1)}\" }"
      )

    unless res1
      vprint_status("#{rhost}:#{rport} No reply to the initial JSON request")
      return
    end

    if res1.code.to_s =~ /^[5]/
      vprint_error("#{rhost}:#{rport} The server replied with #{res1.code} for our initial JSON request, double check TARGETURI and HTTP_METHOD")
      return
    end

    # Deserialize a hash, this should work if YAML deserializes.
    res2 = send_probe("--- {}\n".gsub(':', '\u003a'))

    unless res2
      vprint_status("#{rhost}:#{rport} No reply to the initial YAML probe")
      return
    end

    # Deserialize a malformed object, inducing an error.
    res3 = send_probe("--- !ruby/object:\x00".gsub(':', '\u003a'))

    unless res3
      vprint_status("#{rhost}:#{rport} No reply to the second YAML probe")
      return
    end

    vprint_status("Probe response codes: #{res1.code} / #{res2.code} / #{res3.code}")

    if (res2.code == res1.code) and (res3.code != res2.code) and (res3.code != 200)
      # If first and second requests are the same, and the third is different but not a 200, we're vulnerable.
      print_good("#{rhost}:#{rport} is likely vulnerable due to a #{res3.code} reply for invalid YAML")
      report_vuln({
        :host	=> rhost,
        :port	=> rport,
        :proto  => 'tcp',
        :name	=> self.name,
        :info	=> "Module triggered a #{res3.code} reply",
        :refs   => self.references
      })
    else
      # Otherwise we're not likely vulnerable.
      vprint_status("#{rhost}:#{rport} is not likely to be vulnerable or TARGETURI & HTTP_METHOD must be set")
    end
  end

end