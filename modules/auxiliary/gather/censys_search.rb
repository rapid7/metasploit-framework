##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

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
    ])
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
      @cli = Rex::Proto::Http::Client.new('search.censys.io', 443, {}, true)
      @cli.connect

    if @searchtype.include?('ipv4')
      response = @cli.request_cgi(
        'method' => 'GET',
        'uri' => "/api/v2/hosts/search?q=#{keyword}",
        'headers' => { 'Authorization' => basic_auth_header(@uid, @secret) },
      )
      res = @cli.send_recv(response)
    elsif @searchtype.include?('certificates')
      response = @cli.request_cgi(
        'method' => 'GET',
        'uri' => "/api/v1/view/certificates/#{keyword}",
        'headers' => { 'Authorization' => basic_auth_header(@uid, @secret) },
      )
      res = @cli.send_recv(response)
    end

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed")
    end

    unless res
      print_error('server_response_error')
      return
    end

    records = ActiveSupport::JSON.decode(res.body)

    if @searchtype.include?('certificates')
      parse_certificates(records)
    elsif @searchtype.include?('ipv4')
      parse_ipv4(records['result'])
    end
  end
  def valid_domain?(domain)
    domain =~ /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/
  end

  def domain2ip(domain)
    ips = []
    begin
      ips = Rex::Socket.getaddresses(domain)
    rescue SocketError
    end
    ips
  end

  def parse_certificates(certificate)
    ips = []
    # parsed.fingerprint_sha256
    # parsed.subject_dn
    # parsed.issuer_dn
    subject_dn = certificate['parsed']['subject_dn']
    return unless subject_dn.include?('CN=')

    host = subject_dn.split('CN=')[1]
    if Rex::Socket.is_ipv4?(host)
      ips << host
    elsif valid_domain?(host) # Fake DNS server
      ips |= domain2ip(host)
    end

    ips.each do |ip|
      print_good("#{ip} - #{subject_dn}")
      report_host(:host => ip, :info => subject_dn)
    end
  end

  def parse_ipv4(records)
    return unless records['hits']
    records['hits'].each do |ipv4|
      ip = ipv4['ip']
      services = ipv4['services']
      ports = []
      services.each do |service|
        port = service['port']
        name = service['service_name']
        certificate = service['certificate']
        if certificate
            print_good("#{ipv4['ip']} - #{port} - #{name} - #{certificate}")
        end
        report_service(:host => ip, :port => port, :name => name)
        ports.append(port)
      end
      if ports != nil
        print_good("#{ip} - #{ports.join(',')}")
      end
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
