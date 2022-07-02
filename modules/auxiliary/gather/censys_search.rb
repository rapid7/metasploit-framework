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
      OptString.new('DORK', [true, 'The Censys Search Dork']),
      OptBool.new('CERTIFICATES', [false, 'Query infos about certificates', false])
    ])
  end

  def basic_auth_header(username, password)
    auth_str = username.to_s + ":" + password.to_s
    auth_str = "Basic " + Rex::Text.encode_base64(auth_str)
  end

  def search(keyword)
    # search_type should be one of ipv4, websites, certificates

    begin
      # "80.http.get.headers.server: Apache"
      payload = {
        'query' => keyword
      }
      @cli = Rex::Proto::Http::Client.new('search.censys.io', 443, {}, true)
      @cli.connect

      response = @cli.request_cgi(
        'method' => 'GET',
         'uri' => "/api/v2/hosts/search?q=#{keyword}",
         'headers' => { 'Authorization' => basic_auth_header(@uid, @secret) },
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
    parse_ipv4(records['result'])
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

  def parse_certificate(certificate)
    if certificate.nil?
      return "NO_CERT_DATA"
    end
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

    result = []
    ips.each do |ip|
      result.append("#{ip} - #{subject_dn}")
    end
    return result
  end

  def parse_ipv4(records)
    if records.nil?
      return
    end
    records['hits'].each do |ipv4|
      ip = ipv4['ip']
      services = ipv4['services']
      ports = []
      port_count = 0
      services.each do |service|
        port = service['port']
        name = service['service_name']
        ports.append("#{port}/#{name}")
        port_count += 1
        if @certificates == true
          certificate = service['certificate']
          if certificate
            begin
              response = @cli.request_cgi(
                'method' => 'GET',
                'uri' => "/api/v1/view/certificates/#{certificate}",
                'headers' => { 'Authorization' => basic_auth_header(@uid, @secret) },
              )
              res = @cli.send_recv(response)
            rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
              print_error("HTTP Connection Failed")
            end
            unless res
              print_error('server_response_error')
              return
            end
            cert = ActiveSupport::JSON.decode(res.body)
            ports.append(parse_certificate(cert))
          else
            ports.append("NO_CERT_DATA") #Need to input data for organization
          end
        else
          ports.append("NO_CERT_DATA") #Need to input data for organization
        end
        report_service(:host => ip, :port => port, :name => name)
      end

      if ports != nil
        i = 0
        print_good("#{ip}")
        ports.each do |port|
          if i % 2 == 0 && i / 2 < port_count
            print "#{port} "
          end
          i += 1
        end
        print "\n"
        if @certificate == true
          ports.each do |port|
            if i % 2 == 1 && i / 2 < port_count
              if !port.include? "NO_CERT_DATA"
                port.each do |cert|
                  print_good("#{ports[i-1]} - #{cert}")
                end
              end
            end
            i += 1
          end
        end
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
    @dork = datastore['DORK']
    @certificates = datastore['CERTIFICATES']
    search(@dork)
  end
end
