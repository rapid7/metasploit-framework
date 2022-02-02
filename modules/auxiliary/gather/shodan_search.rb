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
    super(update_info(info,
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
      },
      'Author' =>
        [
          'John H Sawyer <john[at]sploitlab.com>', # InGuardians, Inc.
          'sinn3r'  # Metasploit-fu plus other features
        ],
      'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        OptString.new('SHODAN_APIKEY', [true, 'The SHODAN API key']),
        OptString.new('QUERY', [true, 'Keywords you want to search for']),
        OptString.new('OUTFILE', [false, 'A filename to store the list of IPs']),
        OptBool.new('DATABASE', [false, 'Add search results to the database', false]),
        OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
        OptRegexp.new('REGEX', [true, 'Regex search for a specific IP/City/Country/Hostname', '.*'])

      ])

    deregister_http_client_options
  end

  # create our Shodan query function that performs the actual web request
  def shodan_query(apikey, query, page)
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
    apikey = datastore['SHODAN_APIKEY']
    maxpage = datastore['MAXPAGE']

    # results gets our results from shodan_query
    results = []
    results[0] = shodan_query(apikey, query, 1)

    if results[0]['total'].nil? || results[0]['total'] == 0
      msg = "No results."
      if results[0]['error'].to_s.length > 0
        msg << " Error: #{results[0]['error']}"
      end
      print_error(msg)
      return
    end

    # Determine page count based on total results
    if results[0]['total'] % 100 == 0
      tpages = results[0]['total'] / 100
    else
      tpages = results[0]['total'] / 100 + 1
    end
    maxpage = tpages if datastore['MAXPAGE'] > tpages

    # start printing out our query statistics
    print_status("Total: #{results[0]['total']} on #{tpages} " +
      "pages. Showing: #{maxpage} page(s)")

    # If search results greater than 100, loop & get all results
    print_status('Collecting data, please wait...')

    if results[0]['total'] > 100
      page = 1
      while page < maxpage
        page_result = shodan_query(apikey, query, page+1)
        if page_result['matches'].nil?
          next
        end
        results[page] = page_result
        page += 1
      end
    end

    # Save the results to this table
    tbl = Rex::Text::Table.new(
      'Header'  => 'Search Results',
      'Indent'  => 1,
      'Columns' => ['IP:Port', 'City', 'Country', 'Hostname']
    )

    # Organize results and put them into the table and database
    regex = datastore['REGEX'] if datastore['REGEX']
    results.each do |page|
      page['matches'].each do |host|
        city = host['location']['city'] || 'N/A'
        ip   = host['ip_str'] || 'N/A'
        port = host['port'] || ''
        country = host['location']['country_name'] || 'N/A'
        hostname = host['hostnames'][0]
        data = host['data']

        report_host(:host     => ip,
                    :name     => hostname,
                    :comments => 'Added from Shodan',
                    :info     => host['info']
                    ) if datastore['DATABASE']

        report_service(:host => ip,
                       :port => port,
                       :info => 'Added from Shodan'
                       ) if datastore['DATABASE']

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
    #Show data and maybe save it if needed
    print_line()
    print_line("#{tbl}")
    save_output(tbl) if datastore['OUTFILE']
  end
end
