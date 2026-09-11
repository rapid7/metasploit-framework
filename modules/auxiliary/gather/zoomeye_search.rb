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

  require 'base64'

  def dork_search(resource, dork, page, facets, api_key)
    sub_type = resource == 'web' ? 'web' : 'v4'
    qbase64 = Base64.strict_encode64(dork)
    page_num = page.to_i > 0 ? page.to_i : 1

    # Correct field names according to ZoomEye API v2 documentation
    if resource.include?('host')
      request_fields = 'ip,port,service,product,version,os,banner,country.name,city.name,domain,hostname,protocol'
    else
      request_fields = 'ip,domain,site,country.name,city.name,title,product,app,db,webapp'
    end

    payload = {
      'qbase64'  => qbase64,
      'page'     => page_num,
      'pagesize' => 10,
      'sub_type' => sub_type,
      'fields'   => request_fields
    }

    payload['facets'] = facets unless facets.nil? || facets.to_s.empty?

    res = send_request_cgi({
      'uri'     => '/v2/search',
      'method'  => 'POST',
      'rhost'   => 'api.zoomeye.ai',
      'rport'   => 443,
      'SSL'     => true,
      'headers' => { 'API-KEY' => api_key },
      'ctype'   => 'application/json',
      'data'    => payload.to_json
    })

    if res && res.code == 401
      fail_with(Failure::BadConfig, '401 Unauthorized. Your ZOOMEYE_APIKEY is invalid')
    end

    if res
      begin
        raw_results = ActiveSupport::JSON.decode(res.body)
        parsed_json = raw_results.is_a?(Array) ? raw_results.first : raw_results

        if parsed_json.is_a?(Hash)
          if parsed_json['code'] == 50000
            print_error("ZoomEye API returned an internal error (50000). The query might be malformed: #{dork}")
            return 'server_response_error'
          end

          # Return raw v2 data matches directly without key remapping
          return {
            'matches' => parsed_json['data'] || [],
            'facets'  => parsed_json['facets'] || {},
            'total'   => parsed_json['total'] || 0
          }
        end

        return raw_results
      rescue JSON::ParserError
        return 'server_response_error'
      end
    end
  end

  def match_records?(records)
    # Revert to checking for 'matches', since our dork_search now rebuilds it
    records && records.is_a?(Hash) && records.key?('matches')
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

    #puts JSON.pretty_generate(results)
    if results[0]['total'].nil? || results[0]['total'] == 0
      msg = 'No results.'
      if results[first_page]['error'].present?
        msg << " Error: #{results[0]['error']}"
      end
      print_error(msg)
      return
    end

    # Determine page count based on total results
    if results[first_page]['total'] % 10 == 0
      tpages = results[first_page]['total'] / 10
    else
      tpages = results[first_page]['total'] / 10 + 1
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
      # If search results greater than 10, loop & get all results
      if results[0]['total'] > 10 && maxpage > 1
        print_status('Collecting data, please wait...')
        page = 1
        skipped = 0
        retrying = 0

        while page < maxpage
          page_result = dork_search(resource, dork, page + skipped + 1, facets, api_key)
          if page_result.nil? || page_result['matches'].nil?
            retrying += 1
            if retrying < 3
              next
            else
              retrying = 0
              print_error("Skipping page #{page + skipped + 1}")
              break if page + skipped >= maxpage

              skipped += 1
              next
            end
          else
            retrying = 0
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
      results = [results] unless results.is_a?(Array)

      results.each do |result|
        matches = result.is_a?(Hash) ? (result['matches'] || result['data'] || []) : []

        matches.each do |match|
          city     = match['city.name'] || match.dig('city', 'name') || 'Unknown'
          country  = match['country.name'] || match.dig('country', 'name') || 'Unknown'
          ip       = match['ip'].is_a?(Array) ? match['ip'].first : match['ip']
          protocol = match['protocol'].to_s.downcase
          port     = match['port']
          hostname = match['hostname'] || match['domain'] || ''
          os       = match['os'] || ''
          app      = match['product'] || match['app'] || ''
          service  = match['service'] || 'unknown'
          version  = match['version'] || ''
          info     = match['banner'] || ''

          # Normalize protocol (defaults to 'tcp' if not valid 'tcp' or 'udp')
          protocol = 'tcp' unless %w[tcp udp].include?(protocol)

          if datastore['DATABASE']
            report_host(
              host: ip,
              name: hostname,
              os_name: os,
              comments: dork
            )

            report_service(
              host: ip,
              port: port,
              proto: protocol,
              name: service,
              info: "#{app} running version: #{version}".strip
            )
          end
          if resource == 'web'
            tbl1 << [ip, protocol, city, country, hostname, os, service, app, version, info]
          else
            tbl1 << ["#{ip}:#{port}", protocol, city, country, hostname, os, service, app, version, info]
          end
        end
      end
      print_line(tbl1.to_s)
      save_output(tbl1) if datastore['OUTFILE']
    end
    if datastore['FACETS']
      print_line(facets_tbl.to_s)
      save_output(facets_tbl) if datastore['OUTFILE']
    end
  end
end
