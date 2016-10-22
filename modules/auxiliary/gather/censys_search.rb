##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary

  def initialize(info={})
    super(update_info(info,
      'Name' => 'Censys Search',
      'Description' => %q{
        The module use the Censys REST API to access the same data
        accessible through web interface. The search endpoint allows searches
        against the current data in the IPv4, Top Million Websites, and
        Certificates indexes using the same search syntax as the primary site.
      },
      'Author' => [ 'Nixawk' ],
      'References' => [
        ['URL', 'https://censys.io/api']
      ],
      'License' => MSF_LICENSE
    ))

    register_options([
      OptString.new('CENSYS_UID', [true, 'The Censys API UID']),
      OptString.new('CENSYS_SECRET', [true, 'The Censys API SECRET']),
      OptString.new('CENSYS_DORK', [true, 'The Censys Search Dork']),
      OptEnum.new('CENSYS_SEARCHTYPE', [true, 'The Censys Search Type', 'certificates', ['certificates', 'ipv4', 'websites']])
    ], self.class)
  end

  def basic_auth_header(username, password)
    auth_str = username.to_s + ":" + password.to_s
    auth_str = "Basic " + Rex::Text.encode_base64(auth_str)
  end

  def search(keyword, search_type)
    # search_type should be one of ipv4, websites, certificates

    begin
      # "80.http.get.headers.server: Apache"
      payload = {
        'query' => keyword
      }

      @cli = Rex::Proto::Http::Client.new('www.censys.io', 443, {}, true)
      @cli.connect

      response = @cli.request_cgi(
        'method' => 'post',
        'uri' => "/api/v1/search/#{search_type}",
        'headers' => { 'Authorization' => basic_auth_header(@uid, @secret) },
        'data' => payload.to_json
      )

      res = @cli.send_recv(response)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed")
    end

    unless res
      print_error('server_response_error')
      return
    end

    records = ActiveSupport::JSON.decode(res.body)
    results = records['results']

    if @searchtype.include?('certificates')
      parse_certificates(results)
    elsif @searchtype.include?('ipv4')
      parse_ipv4(results)
    elsif @searchtype.include?('websites')
      parse_websites(results)
    end
  end

  def parse_certificates(records)
    records.each do |certificate|
      # parsed.fingerprint_sha256
      # parsed.subject_dn
      # parsed.issuer_dn
      print_status(certificate['parsed.fingerprint_sha256'].join(','))
      print_status(certificate['parsed.subject_dn'].join(','))
      print_status(certificate['parsed.issuer_dn'].join(','))
    end
  end

  def parse_ipv4(records)
    records.each do |ipv4|
      # ip
      # protocols
      print_status("#{ipv4['ip']} - #{ipv4['protocols'].join(',')}")
    end
  end

  def parse_websites(records)
    records.each do |website|
      # domain
      # alexa_rank
      print_status("#{website['domain']} - #{website['alexa_rank']}")
    end
  end

  # Check to see if www.censys.io resolves properly
  def censys_resolvable?
    begin
      Rex::Socket.resolv_to_dotted("www.censys.io")
    rescue RuntimeError, SocketError
      return false
    end
    true
  end

  def run
    # check to ensure www.censys.io is resolvable
    unless censys_resolvable?
      print_error("Unable to resolve www.censys.io")
      return
    end

    @uid = datastore['CENSYS_UID']
    @secret = datastore['CENSYS_SECRET']
    @dork = datastore['CENSYS_DORK']
    @searchtype = datastore['CENSYS_SEARCHTYPE']
    search(@dork, @searchtype)
  end
end
