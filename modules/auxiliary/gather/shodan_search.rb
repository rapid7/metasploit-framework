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
        'Name' => 'Shodan Search',
        'Description' => %q{
          This module uses the Shodan API to search Shodan. Accounts are free
          and an API key is required to use this module. Output from the module
          is displayed to the screen and can be saved to a file or the MSF database.
          NOTE: SHODAN filters (i.e. port, hostname, os, geo, city) can be used in
          queries, but there are limitations when used with a free API key. Please
          see the Shodan site for more information.
          Shodan website: https://www.shodan.io/
          API: https://developer.shodan.io/api
          Filters: https://www.shodan.io/search/filters
          Facets: https://www.shodan.io/search/facet (from the scrollbox)
        },
        'Author' => [
          'John H Sawyer <john[at]sploitlab.com>', # InGuardians, Inc.
          'sinn3r' # Metasploit-fu plus other features
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        OptString.new('SHODAN_APIKEY', [true, 'The SHODAN API key']),
        OptString.new('QUERY', [true, 'Keywords you want to search for']),
        OptString.new('FACETS', [false, 'List of facets']),
        OptString.new('OUTFILE', [false, 'A filename to store the list of IPs']),
        OptBool.new('DATABASE', [false, 'Add search results to the database', false]),
        OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
        OptRegexp.new('REGEX', [true, 'Regex search for a specific IP/City/Country/Hostname', '.*'])

      ]
    )

    # overwriting the default user-agent. Shodan is checking it and delivering a html response when using the default ua (see #16189 and #16223)
    register_advanced_options(
      [
        OptString.new('UserAgent', [false, 'The User-Agent header to use for all requests', 'Wget/1.21.2 (linux-gnu)' ])
      ]
    )

    deregister_http_client_options
  end

  # create our Shodan query function that performs the actual web request
  def shodan_query(apikey, query, facets, page)
    # send our query to Shodan
    res = send_request_cgi({
      'method' => 'GET',
      'rhost' => 'api.shodan.io',
      'rport' => 443,
      'uri' => '/shodan/host/search',
      'SSL' => true,
      'vars_get' => {
        'key' => apikey,
        'query' => query,
        'facets' => facets,
        'page' => page.to_s
      }
    })

    if res && res.code == 401
      fail_with(Failure::BadConfig, '401 Unauthorized. Your SHODAN_APIKEY is invalid')
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

  # save output to file
  def save_output(data)
    ::File.open(datastore['OUTFILE'], 'wb') do |f|
      f.write(data)
      print_status("Saved results in #{datastore['OUTFILE']}")
    end
  end

  # Check to see if api.shodan.io resolves properly
  def shodan_resolvable?
    begin
      Rex::Socket.resolv_to_dotted("api.shodan.io")
    rescue RuntimeError, SocketError
      return false
    end

    true
  end

  def run
    # check our API key is somewhat sane
    unless /^[a-z\d]{32}$/i.match?(datastore['SHODAN_APIKEY'])
      fail_with(Failure::BadConfig, 'Shodan API key should be 32 characters a-z,A-Z,0-9.')
    end

    # check to ensure api.shodan.io is resolvable
    unless shodan_resolvable?
      print_error("Unable to resolve api.shodan.io")
      return
    end

    # create our Shodan request parameters
    query = datastore['QUERY']
    facets = datastore['FACETS']
    apikey = datastore['SHODAN_APIKEY']
    maxpage = datastore['MAXPAGE']

    # results gets our results from shodan_query
    results = []
    first_page = 0
    results[first_page] = shodan_query(apikey, query, facets, 1)

    if results[first_page]['total'].nil? || results[first_page]['total'] == 0
      msg = "No results."
      if results[first_page]['error'].to_s.length > 0
        msg << " Error: #{results[first_page]['error']}"
      end
      print_error(msg)
      return
    end

    # Determine page count based on total results
    if results[first_page]['total'] % 100 == 0
      tpages = results[first_page]['total'] / 100
    else
      tpages = results[first_page]['total'] / 100 + 1
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
      facet = results.dig(first_page, 'facets')
      facet.each do |name, list|
        list.each do |f|
          facets_tbl << [name.to_s, (f['value']).to_s, (f['count']).to_s]
        end
      end
    else
      # start printing out our query statistics
      print_status("Total: #{results[first_page]['total']} on #{tpages} " +
        "pages. Showing: #{maxpage} page(s)")

      # If search results greater than 100, loop & get all results
      print_status('Collecting data, please wait...')

      if results[first_page]['total'] > 100
        page = 1
        while page < maxpage
          page_result = shodan_query(apikey, query, facets, page + 1)
          if page_result['matches'].nil?
            next
          end

          results[page] = page_result
          page += 1
        end
      end
      # Save the results to this table
      tbl = Rex::Text::Table.new(
        'Header' => 'Search Results',
        'Indent' => 1,
        'Columns' => ['IP:Port', 'City', 'Country', 'Hostname']
      )

      # Organize results and put them into the table and database
      regex = datastore['REGEX'] if datastore['REGEX']
      results.each do |page|
        page['matches'].each do |host|
          city = host.dig('location', 'city') || 'N/A'
          ip = host.fetch('ip_str', 'N/A')
          port = host.fetch('port', '')
          country = host.dig('location', 'country_name') || 'N/A'
          hostname = host.dig('hostnames', 0)
          data = host.dig('data')

          report_host(:host => ip,
                      :name => hostname,
                      :comments => 'Added from Shodan',
                      :info => host.dig('info')) if datastore['DATABASE']

          report_service(:host => ip,
                         :port => port,
                         :info => 'Added from Shodan') if datastore['DATABASE']

          if ip =~ regex ||
             city =~ regex ||
             country =~ regex ||
             hostname =~ regex ||
             data =~ regex
            # Unfortunately we cannot display the banner properly,
            # because it messes with our output format
            tbl << ["#{ip}:#{port}", city, country, hostname]
          end
        end
      end
      # Show data and maybe save it if needed
      print_line()
      print_line("#{tbl}")
      save_output(tbl) if datastore['OUTFILE']
    end
    if datastore['FACETS']
      print_line(facets_tbl.to_s)
      save_output(facets_tbl) if datastore['OUTFILE']
    end
  end
end
