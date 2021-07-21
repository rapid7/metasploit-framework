##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/https'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ZoomEye Search',
        'Description' => %q{
          The module use the ZoomEye API to search ZoomEye.ZoomEye is a cyberspace search engine,
          users can search for network devices using a browser.
        },
        'Author' => [
          'Nixawk', # Original
          'wh0am1i' # Rewrite
        ],
        'References' => [
          ['URL', 'https://www.zoomeye.org/api/doc'],
          ['URL', 'https://github.com/knownsec/ZoomEye-python']
        ],
        'License' => MSF_LICENSE
      )
    )
    register_options(
      [
        OptString.new('APIKEY', [true, 'The ZoomEye API KEY']),
        OptString.new('ZOOMEYE_DORK', [true, 'The ZoomEye dork']),
        OptEnum.new('RESOURCE', [true, 'ZoomEye Resource Type', 'host', ['host', 'web']]),
        OptString.new('FACETS', [false, 'Query the distribution of the full data of the dork']),
        OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
        OptBool.new('DATABASE', [false, 'Add search results to the database', false]),
        OptBool.new('OUTFILE', [false, 'A filename to store ZoomEye search raw data']),
      ]
    )
    deregister_http_client_options
  end

  def zoomeye_resolvable?
    begin
      Rex::Socket.resolv_to_dotted('api.zoomeye.org')
    rescue RuntimeError, SocketError
      return false
    end
    true
  end

  def search_dork(apikey, dork, resource, page, facet)
    ## search_dork(apikey, dork, resource, page, facet)
    # param: apikey, string, zoomeye API Key
    # param: dork, string, zoomeye dork
    # param: resource, string, search type host or web
    # param: page, int, page num
    # param: facet, string, query the distribution of the full data of the dork
    res = send_request_cgi({
      'method' => 'GET',
      'rhost' => 'api.zoomeye.org',
      'rport' => 443,
      'uri' => "/#{resource}/search",
      'SSL' => true,
      'headers' => { 'API-KEY' => apikey.to_s },
      'vars_get' => {
        'query' => dork,
        'page' => page,
        'facet' => facet
      }
    })
    if res && res.code == 401
      fail_with(Failure::NoAccess, '401 Unauthorized. Your ZoomEye API Key is invalid')
    end
    if res
      results = ActiveSupport::JSON.decode(res.body)
      return results
    else
      return 'Server error!'
    end
  end

  def parse_web_resource(data)
    tab = Rex::Text::Table.new(
      'Header' => 'Web Search Result',
      'Indent' => 1,
      'Columns' => ['IP', 'Site', 'City', 'Country']
    )

    data.each do |match|
      host = match['ip'][0]
      site = match['site']
      city = match['geoinfo']['city']['names']['en']
      country = match['geoinfo']['country']['names']['en']
      tab << [host, site, city, country]

      next unless datastore['DATABASE']

      report_host(host: host,
                  name: site,
                  comments: 'Added from ZoomEye Web Resource')
    end
    print_line(tab.to_s)
  end

  def parse_host_resource(data)
    tab = Rex::Text::Table.new(
      'Header' => 'Web Search Result',
      'Indent' => 1,
      'Columns' => ['IP:Port', 'City', 'Country', 'Service']
    )

    data.each do |match|
      host = match['ip']
      port = match['portinfo']['port']
      city = match['geoinfo']['city']['names']['en']
      country = match['geoinfo']['country']['names']['en']
      service = match['portinfo']['service']

      tab << ["#{host}:#{port}", city, country, service]

      next unless datastore['DATABASE']

      report_host(host: host,
                  info: "Port:#{port}",
                  comments: 'Added from ZoomEye Host Resource')
    end
    print_line(tab.to_s)
  end

  def parse_facets(filed, data)
    # parse facet field,
    # host resource support field: 'product', 'device','service', 'os', 'port', 'country', 'city'
    # web resource suppoty field:  "webapp","component","framework","server", "waf","os","country"
    field_arr = filed.split(',')

    field_arr.each do |item|
      tab = Rex::Text::Table.new(
        'Header' => 'Facets Search Result',
        'Indent' => 1,
        'Columns' => [item, 'count']
      )
      data[item].each do |match|
        name = match['name']
        number = match['count']
        tab << [name, number]
      end
      print_line(tab.to_s)
    end
  end

  def save_raw_data(dork, data)
    filename = dork.gsub(/[^a-zA-Z ]/, '_')
    ::File.open("#{filename}.json", 'wb') do |f|
      f.write(ActiveSupport::JSON.encode(data))
      print_status("Save ZoomEye Result in #{filename}.json")
    end
  end

  def run
    unless zoomeye_resolvable?
      print_error('Unable to resolve api.zoomeye.org')
      return
    end

    dork = datastore['ZOOMEYE_DORK']
    resource = datastore['RESOURCE']
    page = datastore['MAXPAGE']
    apikey = datastore['APIKEY']
    facets = datastore['FACETS']
    resp_data = []
    1.upto(datastore['MAXPAGE']) do |current_page|
      results = search_dork(apikey, dork, resource, current_page, facets)
      unless results && results.key?('matches')
        fail_with(Failure::NotFound, "Not Found #{dork} from ZoomEye!")
      end
      resp_data.append(results)
    end

    resp_data.each do |item|
      matches = item['matches']
      if resource.include?('web')
        parse_web_resource(matches)
      else
        parse_host_resource(matches)
      end
    end

    facet_data = results['facets']
    unless facets.nil?
      parse_facets(facets, facet_data)
    end
    save_raw_data(dork, resp_data) if datastore['OUTFILE']
    print_status("Total:#{results['total']} Current: #{page * 20}")
  end

end
