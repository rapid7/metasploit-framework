##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report


  def initialize(info={})
    super(update_info(info,
      'Name'        => 'ZoomEye Search',
      'Description' => %q{
        The module use the ZoomEye API to search ZoomEye. ZoomEye is a search
        engine for cyberspace that lets the user find specific network
        components(ip, services, etc.).
      },
      'Author'      => [ 'Nixawk' ],
      'References'  => [
        ['URL', 'https://github.com/zoomeye/SDK'],
        ['URL', 'https://www.zoomeye.org/api/doc'],
        ['URL', 'https://www.zoomeye.org/help/manual']
      ],
      'License'     => MSF_LICENSE
      ))

      register_options(
        [
          OptString.new('USERNAME', [true, 'The ZoomEye username']),
          OptString.new('PASSWORD', [true, 'The ZoomEye password']),
          OptString.new('ZOOMEYE_DORK', [true, 'The ZoomEye dork']),
          OptEnum.new('RESOURCE', [true, 'ZoomEye Resource Type', 'host', ['host', 'web']]),
          OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1])
        ])
  end

  # Check to see if api.zoomeye.org resolves properly
  def zoomeye_resolvable?
    begin
      Rex::Socket.resolv_to_dotted("api.zoomeye.org")
    rescue RuntimeError, SocketError
      return false
    end

    true
  end

  def login(username, password)
    # See more: https://www.zoomeye.org/api/doc#login

    access_token = ''
    @cli = Rex::Proto::Http::Client.new('api.zoomeye.org', 443, {}, true)
    @cli.connect

    data = {'username' => username, 'password' => password}
    req = @cli.request_cgi({
      'uri'    => '/user/login',
      'method' => 'POST',
      'data'   => data.to_json
    })

    res = @cli.send_recv(req)

    unless res
      print_error('server_response_error')
      return
    end

    records = ActiveSupport::JSON.decode(res.body)
    access_token = records['access_token'] if records && records.key?('access_token')
    access_token
  end

  def dork_search(dork, resource, page)
    # param: dork
    #        ex: country:cn
    #        access https://www.zoomeye.org/search/dorks for more details.
    # param: page
    #        total page(s) number
    # param: resource
    #        set a search resource type, ex: [web, host]
    # param: facet
    #        ex: [app, device]
    #         A comma-separated list of properties to get summary information

    begin
      req = @cli.request_cgi({
        'uri'      => "/#{resource}/search",
        'method'   => 'GET',
        'headers'  => { 'Authorization' => "JWT #{@zoomeye_token}" },
        'vars_get' => {
          'query'  => dork,
          'page'   => page,
          'facet'  => 'ip'
        }
      })

      res = @cli.send_recv(req)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed")
    end

    unless res
      print_error('server_response_error')
      return
    end

    # Invalid Token, Not enough segments
    # Invalid Token, Signature has expired
    if res.body =~ /Invalid Token, /
      fail_with(Failure::BadConfig, '401 Unauthorized. Your ZOOMEYE_APIKEY is invalid')
    end

    ActiveSupport::JSON.decode(res.body)
  end

  def match_records?(records)
    records && records.key?('matches')
  end

  def parse_host_records(records)
    records.each do |match|
      host = match['ip']
      port = match['portinfo']['port']

      report_service(:host => host, :port => port)
      print_good("Host: #{host} ,PORT: #{port}")
    end
  end

  def parse_web_records(records)
    records.each do |match|
      host = match['ip'][0]
      domains = match['domains']

      report_host(:host => host)
      print_good("Host: #{host}, Domains: #{domains}")
    end
  end

  def run
    # check to ensure api.zoomeye.org is resolvable
    unless zoomeye_resolvable?
      print_error("Unable to resolve api.zoomeye.org")
      return
    end

    @zoomeye_token = login(datastore['USERNAME'], datastore['PASSWORD'])
    if @zoomeye_token.blank?
      print_error("Unable to login api.zoomeye.org")
      return
    end

    # create ZoomEye request parameters
    dork = datastore['ZOOMEYE_DORK']
    resource = datastore['RESOURCE']
    page = 1
    maxpage = datastore['MAXPAGE']

    # scroll max pages from ZoomEye
    while page <= maxpage
      print_status("ZoomEye #{resource} Search: #{dork} - page: #{page}")
      results = dork_search(dork, resource, page) if dork
      break unless match_records?(results)

      matches = results['matches']
      if resource.include?('web')
        parse_web_records(matches)
      else
        parse_host_records(matches)
      end
      page += 1
    end
  end
end
