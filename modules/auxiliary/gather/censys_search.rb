##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  CENSYS_SEARCH_API = 'search.censys.io'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Censys Search',
        'Description' => %q{
          The module uses the Censys REST API to access the same data accessible
          through the web interface. The search endpoint allows queries using
          the Censys Search Language against the Hosts dataset. Setting the
          CERTIFICATES option will also retrieve the certificate details for each
          relevant service by querying the Certificates dataset.
        },
        'Author' => [
          'Nixawk', # original Metasploit module
          'e2002e', # rework to use the API v2
          'Christophe De La Fuente' # rework to use the API v2
        ],
        'References' => [
          ['URL', 'https://search.censys.io']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('CENSYS_UID', [true, 'The Censys API UID']),
      OptString.new('CENSYS_SECRET', [true, 'The Censys API SECRET']),
      OptString.new('QUERY', [true, 'The Censys search query']),
      OptBool.new('CERTIFICATES', [false, 'Query infos about certificates', false])
    ])
  end

  def basic_auth_header
    auth_str = datastore['CENSYS_UID'].to_s + ':' + datastore['CENSYS_SECRET'].to_s
    'Basic ' + Rex::Text.encode_base64(auth_str)
  end

  def search(keyword)
    begin
      @cli = Rex::Proto::Http::Client.new(CENSYS_SEARCH_API, 443, {}, true)
      @cli.connect

      response = @cli.request_cgi(
        'method' => 'GET',
        'uri' => "/api/v2/hosts/search?q=#{keyword}",
        'headers' => { 'Authorization' => basic_auth_header }
      )
      res = @cli.send_recv(response)
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
      fail_with(Failure::Unreachable, "#search: HTTP Connection Failed: #{e}")
    end
    fail_with(Failure::Unreachable, '#search: HTTP Connection Failed') unless res

    records = ActiveSupport::JSON.decode(res.body)
    if records['code'] == 200
      parse_record(records['result'])
    else
      fail_with(Failure::UnexpectedReply, "Error returned by '/api/v2/hosts/search': code=#{records['code']}, status=#{records['status']}, error=#{records['error']}")
    end
  end

  def get_certificate_details(cert_fingerprint)
    return if cert_fingerprint.nil?

    begin
      response = @cli.request_cgi(
        'method' => 'GET',
        'uri' => "/api/v1/view/certificates/#{cert_fingerprint}",
        'headers' => { 'Authorization' => basic_auth_header }
      )
      res = @cli.send_recv(response)
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('#get_certificate_details - HTTP Connection Failed')
      return
    end
    return unless res

    cert_details = ActiveSupport::JSON.decode(res.body)
    subject = cert_details.dig('parsed', 'subject_dn')
    return unless subject

    issuer = cert_details.dig('parsed', 'issuer_dn')
    cert_details = subject
    cert_details << " (Issuer: #{issuer})" if issuer
    cert_details
  end

  def parse_record(records)
    unless records&.dig('hits')&.any?
      print_error('The query did not return any records')
      return
    end
    records['hits'].each do |hit|
      ip = hit['ip']
      services = hit['services']
      ports = []
      certs = []
      services.each do |service|
        port = service['port']
        name = service['service_name']
        ports << "#{port}/#{name}"
        cert_details = nil
        if datastore['CERTIFICATES'] && service['certificate']
          cert_details = get_certificate_details(service['certificate'])
          if cert_details
            certs << "Certificate for #{port}/#{name}: #{cert_details}"
          else
            vprint_error("Unable to get certificate details for #{port}/#{name}")
          end
        end
        if cert_details
          report_service(host: ip, port: port, name: name, info: cert_details)
        else
          report_service(host: ip, port: port, name: name)
        end
      end
      print_good("#{ip} - #{ports.join(',')}")
      certs.each { |cert| print_status(cert) }
    end
  end

  # Check to see if Censys Search API host resolves properly
  def censys_resolvable?
    begin
      Rex::Socket.resolv_to_dotted(CENSYS_SEARCH_API)
    rescue RuntimeError, SocketError
      return false
    end
    true
  end

  def run
    unless censys_resolvable?
      fail_with(Failure::Unreachable, "Unable to resolve #{CENSYS_SEARCH_API}")
    end

    search(datastore['QUERY'])
  end
end
