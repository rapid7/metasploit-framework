##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    @domain = 'ai'
    super(
      update_info(
        info,
        'Name' => 'ZoomEye Search',
        'Description' => %q{
          The module use the ZoomEye API to search ZoomEye. ZoomEye is a search
          engine for cyberspace that lets the user find specific network
          components(ip, services, etc.).

          Setting facets will output a simple report on the overall search. It's values are:
          Host search: app, device, service, os, port, country, city
          Web search: webapp, component, framework, frontend, server, waf, os, country, city

          Possible filters values are:
          Host search: app, ver, device, os, service, ip, cidr, hostname, port, city, country, asn
          Web search: app, header, keywords, desc, title, ip, site, city, country

          When using multiple filters, you must enclose individual filter values in double quotes, separating filters with the '+' symbol as follows:
          'country:"FR" + os:"Linux"'
        },
        'Author' => [
          'Nixawk', # Original Author
          'Yvain', # Initial improvements
          'Grant Willcox' # Additional fixes to refine searches, improve quality of info saved and improve error handling.
        ],
        'References' => [
          ['URL', "https://github.com/knownsec/ZoomEye-python"],
          ['URL', "https://www.zoomeye.#@domain/api/doc"],
          ['URL', "https://www.zoomeye.#@domain/help/manual"]
        ],
        'License' => MSF_LICENSE
      )
    )
    register_options(
      [
        OptString.new('ZOOMEYE_APIKEY', [true, 'The ZoomEye api key']),
        OptString.new('ZOOMEYE_DORK', [true, 'The ZoomEye dork']),
        OptString.new('FACETS', [false, 'A comma-separated list of properties to get summary information on query', nil]),
        OptEnum.new('RESOURCE', [true, 'ZoomEye Resource Type', 'host', ['host', 'web']]),
        OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
        OptString.new('OUTFILE', [false, 'Path to the file to store the resulting table of info']),
        OptBool.new('DATABASE', [false, 'Add search results to the database', false])
      ]
    )

    register_advanced_options(
      [
        OptString.new('UserAgent', [false, 'The User-Agent header to use for all requests', 'Wget/1.21.2 (linux-gnu)' ])
      ]
    )
    deregister_http_client_options
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
      Rex::Socket.resolv_to_dotted("api.zoomeye.#@domain")
    rescue RuntimeError, SocketError
      return false
    end
    true
  end

  def dork_search(resource, dork, page, facets, api_key)
    res = send_request_cgi({
      'uri' => "/#{resource}/search",
      'method' => 'GET',
      'rhost' => "api.zoomeye.#@domain",
      'rport' => 443,
      'SSL' => true,
      'headers' => { 'API-KEY' => api_key },
      'vars_get' => {
        'query' => dork,
        'page' => page.to_s,
        'facets' => facets
      }
    })

    if res && res.code == 401
      fail_with(Failure::BadConfig, '401 Unauthorized. Your ZOOMEYE_APIKEY is invalid')
    end
    # Check if we can resolve host, got a response,
    # then parse the JSON, and return it
    if res
      results = ActiveSupport::JSON.decode(res.body)
      return results
    else
      return 'server_response_error'
    end
  end

  def match_records?(records)
    records && records.key?('matches')
  end

  def run
    dork = datastore['ZOOMEYE_DORK']
    resource = datastore['RESOURCE']
    maxpage = datastore['MAXPAGE']
    facets = datastore['FACETS']
    api_key = datastore['ZOOMEYE_APIKEY']
    # check to ensure api.zoomeye.org is resolvable
    unless zoomeye_resolvable?
      print_error("Unable to resolve api.zoomeye.#@domain")
      return
    end

    first_page = 0
    results = []
    results[0] = dork_search(resource, dork, 1, facets, api_key)

    if results[0]['total'].nil? || results[0]['total'] == 0
      msg = 'No results.'
      if results[first_page]['error'].present?
        msg << " Error: #{results[0]['error']}"
      end
      print_error(msg)
      return
    end

    # Determine page count based on total results
    if results[first_page]['total'] % 20 == 0
      tpages = results[first_page]['total'] / 20
    else
      tpages = results[first_page]['total'] / 20 + 1
    end
    maxpage = tpages if datastore['MAXPAGE'] > tpages

    if facets
      facets_tbl = Rex::Text::Table.new(
        'Header' => 'Facets',
        'Indent' => 1,
        'Columns' => ['Facet', 'Name', 'Count']
      )
      print_status("Total: #{results[first_page]['total']} on #{tpages} " \
        'pages. Showing facets')
      facet = results[first_page]['facets']
      facet.each do |name, list|
        list.each do |f|
          facets_tbl << [name.to_s, (f['name']).to_s, (f['count']).to_s]
        end
      end
    else
      print_status("Total: #{results[first_page]['total']} on #{tpages} " \
        "pages. Showing: #{maxpage} page(s)")
      # If search results greater than 20, loop & get all results
      if results[first_page]['total'] > 20
        print_status('Collecting data, please wait...')
        page = 1
        while page < maxpage
          page_result = dork_search(resource, dork, page + 1, facets, api_key)
          if page_result['matches'].nil?
            next
          end

          results[page] = page_result
          page += 1
        end
      end
      tbl1 = Rex::Text::Table.new(
        'Header' => 'Host search',
        'Indent' => 1,
        'Columns' => ['IP:Port', 'Protocol', 'City', 'Country', 'Hostname', 'OS', 'Service', 'AppName', 'Version', 'Info']
      )
      tbl2 = Rex::Text::Table.new(
        'Header' => 'Web search',
        'Indent' => 1,
        'Columns' => ['IP', 'Site', 'City', 'Country', 'DB:Version', 'WebApp:Version']
      )
      # scroll max pages from ZoomEye
      results.each do |result|
        result['matches'].each do |match|
          city = match['geoinfo']['city']['names']['en']
          country = match['geoinfo']['country']['names']['en']
          if resource.include?('host')
            ip = match['ip']
            protocol = match['protocol']['transport']
            port = match['portinfo']['port']
            hostname = match['portinfo']['hostname']
            os = match['portinfo']['os']
            app = match['portinfo']['app']
            service = match['portinfo']['service']
            version = match['portinfo']['version']
            info = match['portinfo']['info']
            if datastore['DATABASE']
              report_host(host: ip,
                          name: hostname,
                          os_name: os,
                          comments: 'Added from Zoomeye')
            end
            if datastore['DATABASE']
              protocol = 'tcp' if ((protocol != 'tcp') || (protocol != 'udp'))
              report_service(host: ip,
                             port: port,
                             proto: protocol,
                             name: service,
                             info: "#{app} running version: #{version}")
            end
            tbl1 << ["#{ip}:#{port}", protocol, city, country, hostname, os, service, app, version, info]
          else
            ips = match['ip']
            site = match['site']
            database = match['db']
            if database.empty?
              db_info = ""
            else
              db_info = database.map { |db|
                if !db['name']&.empty? && !db['version']&.empty?
                  "#{db['name']}:#{db['version']}"
                else
                  ""
                end
              }
            end
            webapp = match['webapp']
            if webapp.empty?
              wa_info = ""
            else
              wa_info = webapp.map { |wa|
                if !wa['name']&.empty? && !wa['version']&.empty?
                  "#{wa['name']}:#{wa['version']}"
                else
                  ""
                end
              }
            end
            if datastore['DATABASE']
              for ip in ips
                report_host(host: ip, name: site, comments: 'Added from Zoomeye')
              end
            end
            for ip in ips
              tbl2 << [ip, site, city, country, db_info, wa_info]
            end
          end
        end
      end
      if resource.include?('host')
        print_line(tbl1.to_s)
        save_output(tbl1) if datastore['OUTFILE']
      else
        print_line(tbl2.to_s)
        save_output(tbl2) if datastore['OUTFILE']
      end
    end
    if datastore['FACETS']
      print_line(facets_tbl.to_s)
      save_output(facets_tbl) if datastore['OUTFILE']
    end
  end
end
