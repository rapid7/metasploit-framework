##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
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
        Beware to properly enclose the whole request with single quotes and limit the span of filters with double quotes:
        `set zoomeye_dork 'country:"france"+some+query'`
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
          OptEnum.new('FACETS', [false, 'A comma-separated list of properties to get summary information on query', nil, ['app', 'device', 'service', 'os', 'port', 'country', 'city']]),
          OptEnum.new('RESOURCE', [true, 'ZoomEye Resource Type', 'host', ['host', 'web']]),
          OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
          OptString.new('OUTFILE', [false, 'A filename to store the list of IPs']),
          OptBool.new('DATABASE', [false, 'Add search results to the database', false])
       ])
  end
  # save output to file
  def save_output(data)
    ::File.open(datastore['OUTFILE'], 'wb') do |f|
      f.write(data)
      print_status("Saved results in #{datastore['OUTFILE']}")
    end
  end

  # Check to see if api.zoomeye.org resolves properly
  def zoomeye_resolvable?
    begin
      Rex::Socket.resolv_to_dotted("api.zoomeye.org")
    rescue RuntimeError, SocketError
      return false
    end
    return true
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

  def dork_search(resource, dork, page, facets)
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
          'facet'  => facets
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

  def run
    dork = datastore['ZOOMEYE_DORK']
    resource = datastore['RESOURCE']
    maxpage = datastore['MAXPAGE']
    facets = datastore['FACETS']
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

    results = []
    results[0] = dork_search(resource, dork, 1, facets)

    if results[0]['total'].nil? || results[0]['total'] == 0
      msg = "No results."
      if results[0]['error'].to_s.length > 0
        msg << " Error: #{results[0]['error']}"
      end
      print_error(msg)
      return
    end

    # Determine page count based on total results
    if results[0]['total'] % 20 == 0
      tpages = results[0]['total'] / 20
    else
      tpages = results[0]['total'] / 20 + 1
    end
    maxpage = tpages if datastore['MAXPAGE'] > tpages

    print_status("Total: #{results[0]['total']} on #{tpages} " +
      "pages. Showing: #{maxpage} page(s)")

    # If search results greater than 20, loop & get all results
    if results[0]['total'] > 20
      print_status('Collecting data, please wait...')
      page = 1
      while page < maxpage
        page_result = dork_search(resource, dork, page+1, facets)
        if page_result['matches'].nil?
          next
        end
        results[page] = page_result
        page += 1
      end
    end

    tbl1 = Rex::Text::Table.new(
      'Header'  => 'Search Results',
      'Indent'  => 1,
      'Columns' => ['IP:Port', 'City', 'Country', 'Hostname', 'OS', 'Service:Version', 'Info']
    )
    tbl2 = Rex::Text::Table.new(
      'Header'  => 'Search Results',
      'Indent'  => 1,
      'Columns' => ['IP', 'Site', 'City', 'Country', 'DB:Version', 'WebApp:Version']
    )
    page = 0
    # scroll max pages from ZoomEye
    results.each do |page|
      page['matches'].each do |match|
        if resource.include?('host')
          ip = match['ip']
          port = match['portinfo']['port']
          city = match['geoinfo']['city']['names']['en']
          country = match['geoinfo']['country']['names']['en']
          hostname = match['portinfo']['hostname']
          os = match['portinfo']['os']
          service = match['portinfo']['app']
          name = match['portinfo']['name']
          version = match['portinfo']['version']
          info = match['portinfo']['extrainfo']
          report_host(:host     => ip,
                      :name     => hostname,
                      :os_name  => os,
                      :comments => 'Added from Zoomeye'
                      ) if datastore['DATABASE']
          report_service(:host => ip,
                         :port => port,
                         :proto => name,
                         :name => "#{service}:#{version}",
                         :info => info
                         ) if datastore['DATABASE']
          tbl1 << ["#{ip}:#{port}", city, country, hostname, os, "#{service}:#{version}", info]
        else
          ip = match['ip']
          site = match['site']
          city = match['geoinfo']['city']['names']['en']
          country = match['geoinfo']['country']['names']['en']
          database = match['db']
          dbInfo = ''
          database.each do |db|
            dbInfo << "#{db['name']}:"
            dbInfo << "#{db['version']}\n"
          end
          webapp = match['webapp']
          waInfo = ''
          webapp.each do |wa|
            waInfo << "#{wa['name']}:"
            waInfo << "#{wa['version']}\n"
          end
          report_host(:host     => ip,
                      :name     => site,
                      :comments => 'Added from Zoomeye'
                      ) if datastore['DATABASE']
          tbl2 << [ip, site, city, country, dbInfo, waInfo]
        end
      end
    end
    print_line()
    if resource.include?('host')
      print_line("#{tbl1}")
      save_output(tbl1) if datastore['OUTFILE']
    else
      print_line("#{tbl2}")
      save_output(tbl2) if datastore['OUTFILE']
    end
  end
end
