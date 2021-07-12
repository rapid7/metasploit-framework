##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Modified on Nixawk's code
##



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
                      'Author'      => [ 'wh0am1i' ],
                      'References'  => [
                        ['URL', 'https://www.zoomeye.org/api/doc'],
                        ['URL', 'https://www.zoomeye.org/help/manual'],
                        ['URL', 'https://github.com/knownsec/ZoomEye-python'],
                      ],
                      'License'     => MSF_LICENSE
          ))

    register_options(
      [
        OptString.new('APIKEY', [true, 'The ZoomEye API KEY']),
        OptString.new('DORK', [true, 'The ZoomEye dork']),
        OptEnum.new('RESOURCE', [true, 'ZoomEye Resource Type', 'host', ['host', 'web']]),
        OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
        OptBool.new('DATABASE', [false, 'Add search results to the database', false]),
        OptBool.new('OUTFILE', [false, 'A filename to store ZoomEye search raw data']),
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

  def dork_search(dork, resource, page, api_key)
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

    cli = Rex::Proto::Http::Client.new('api.zoomeye.org', 443, {}, true)
    cli.connect

    begin
      req = cli.request_cgi({
                              'uri'      => "/#{resource}/search",
                              'method'   => 'GET',
                              'headers'  => { 'API-KEY' => " #{api_key}" },
                              'vars_get' => {
                                'query'  => dork,
                                'page'   => page
                              }
                            })
      res = cli.send_recv(req)
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
    tbl = Rex::Text::Table.new(
      'Header'  => 'Search Results',
      'Indent'  => 1,
      'Columns' => ['IP:Port', 'City', 'Country', 'Hostname']
    )
    records.each do |match|
      host = match['ip']
      port = match['portinfo']['port']
      city = match['geoinfo']['city']['names']['en']
      country = match['geoinfo']['country']['names']['en']
      hostname = match['portinfo']['hostname']
      service = match['portinfo']['service']

      tbl << ["#{host}:#{port}", city, country, hostname]

      report_host(:host     => host,
                  :name     => hostname,
                  :comments => 'Added from ZoomEye Host Search',
                  :info     => "service: #{service}",
                  ) if datastore['DATABASE']

      report_service(:host => host,
                     :port => port,
                     :info => 'Added from ZoomEye Host Search'
      ) if datastore['DATABASE']
    end
    print_line("#{tbl}")
  end

  def parse_web_records(records)
    tbl = Rex::Text::Table.new(
      'Header'  => 'Search Results',
      'Indent'  => 1,
      'Columns' => ['IP', 'City', 'Country', 'Domains']
    )

    records.each do |match|
      host = match['ip'][0]
      domains = match['domains']
      city = match['geoinfo']['city']['names']['en']
      country = match['geoinfo']['country']['names']['en']

      tbl << ["#{host}", city, country, domains]

      report_host(:host     => host,
                  :comments => 'Added from ZoomEye Web Search',
                  :info     => "domains: #{domains}",
                  ) if datastore['DATABASE']

      report_service(:host => host,
                     :domain => domains,
                     :info => 'Added from ZoomEye Web Search'
      ) if datastore['DATABASE']

    end
    print_line("#{tbl}")
  end

  # save ZoomEye raw data to file
  def save_output(raw, dork, page)
    name =dork.gsub(/[^a-zA-Z ]/,'_')
    ::File.open("#{name}_#{page}.json", "wb") do |f|
      f.write(ActiveSupport::JSON.encode(raw))
      print_status("Saved results in #{datastore['OUTFILE']}")
    end
  end

  def run
    # check to ensure api.zoomeye.org is resolvable
    unless zoomeye_resolvable?
      print_error("Unable to resolve api.zoomeye.org")
      return
    end

    # create ZoomEye request parameters
    dork = datastore['DORK']
    resource = datastore['RESOURCE']
    page = 1
    maxpage = datastore['MAXPAGE']
    api_key = datastore['APIKEY']
    results = {}
    # scroll max pages from ZoomEye
    while page <= maxpage
      print_status("ZoomEye #{resource} Search: #{dork} - page: #{page}")
      results = dork_search(dork, resource, page, api_key) if dork
      break unless match_records?(results)
      save_output(results, dork, page) if datastore['OUTFILE']

      matches = results['matches']
      if resource.include?('web')
        parse_web_records(matches)
      else
        parse_host_records(matches)
      end
      page += 1
    end
    # calc current page
    if results['total'] % 20 == 0
      total_page = results['total'] / 20
    else
      total_page = results['total'] / 20 + 1
    end
    print_status("Total:#{results['total']} on #{total_page} Pages\n" +
                   "Showing #{page - 1} page(s)."
    )
  end
end
