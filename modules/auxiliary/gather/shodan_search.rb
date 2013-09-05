##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'net/dns'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Shodan Search',
      'Description' => %q{
        This module uses the SHODAN API to query the database and
        returns the first 50 IPs. SHODAN accounts are free & output
        can be sent to a file for use by another program. Results
        can also populated into the services table in the database.
        NOTE: SHODAN filters (port, hostname, os, geo, city) can be
        used in queries, but the free API does not allow net, country,
        before, and after filters. An unlimited API key can be
        purchased from the Shodan site to use those queries. The 50
        result limit can also be raised to 10,000 for a small fee.
        API: http://www.shodanhq.com/api_doc
        FILTERS: http://www.shodanhq.com/help/filters
      },
      'Author' =>
        [
          'John Sawyer <johnhsawyer[at]gmail.com>',  #sploitlab.com
          'sinn3r'  #Metasploit-fu plus other features
        ],
      'License' => MSF_LICENSE
    ))

    # disabling all the unnecessary options that someone might set to break our query
    deregister_options('RPORT','RHOST', 'DOMAIN',
      'DigestAuthIIS', 'SSLVersion', 'NTLM::SendLM', 'NTLM::SendNTLM',
      'NTLM::SendSPN', 'NTLM::UseLMKey', 'NTLM::UseNTLM2_session',
      'NTLM::UseNTLMv2','SSL')

    register_options(
      [
        OptString.new('SHODAN_APIKEY', [true, "The SHODAN API key"]),
        OptString.new('QUERY', [true, "Keywords you want to search for"]),
        OptString.new('OUTFILE', [false, "A filename to store the list of IPs"]),
        OptBool.new('DATABASE', [false, "Add search results to the database", false]),
        OptInt.new('MAXPAGE', [true, "Max amount of pages to collect", 1]),
        OptString.new('FILTER', [false, 'Search for a specific IP/City/Country/Hostname']),
        OptString.new('VHOST', [true, 'The virtual host name to use in requests', 'www.shodanhq.com']),
      ], self.class)
  end

  # create our Shodan query function that performs the actual web request
  def shodan_query(query, apikey, page)
    # send our query to Shodan
    uri = "/api/search?&q=" + Rex::Text.uri_encode(query) + "&key=" + apikey + "&page=" + page.to_s
    res = send_request_raw(
      {
        'method'   => 'GET',
        'uri'      => uri
    }, 25)

    # Check if we got a response, parse the JSON, and return it
    if (res)
      results = ActiveSupport::JSON.decode(res.body)
      return results
    else
      return 'server_error'
    end
  end

  def save_output(data)
    f = ::File.open(datastore['OUTFILE'], "wb")
    f.write(data)
    f.close
    print_status("Save results in #{datastore['OUTFILE']}")
  end

  def cleanup
    datastore['RHOST'] = @old_rhost
    datastore['RPORT'] = @old_rport
  end

  def run
    # create our Shodan request parameters
    query = datastore['QUERY']
    apikey = datastore['SHODAN_APIKEY']

    @res = Net::DNS::Resolver.new()
    dns_query = @res.query("#{datastore['VHOST']}", "A")
    if dns_query.answer.length == 0
      print_error("Could not resolve #{datastore['VHOST']}")
      return
    else
      # Make a copy of the original rhost
      @old_rhost = datastore['RHOST']
      @old_rport = datastore['RPORT']
      datastore['RHOST'] = dns_query.answer[0].to_s.split(/[\s,]+/)[4]
      datastore['RPORT'] = 80
    end

    page = 1

    # results gets our results from shodan_query
    results = []
    results[page] = shodan_query(query, apikey, page)

    if results[page].empty?
      print_error("No Results Found!")
      return
    end

    # Determine page count based on total results
    if results[page]['total']%50 == 0
      tpages = results[page]['total']/50
    else
      tpages = results[page]['total']/50 + 1
    end

    # start printing out our query statistics
    print_status("Total: #{results[page]['total']} on #{tpages} pages. Showing: #{datastore['MAXPAGE']}")
    print_status("Country Statistics:")
    results[page]['countries'].each { |ctry|
      print_status "\t#{ctry['name']} (#{ctry['code']}): #{ctry['count']}"
    }

    # If search results greater than 50, loop & get all results
    print_status("Collecting data, please wait...")
    if (results[page]['total'] > 50)
      page += 1
      while page <= tpages
        results[page] = shodan_query(query, apikey, page)
        page +=1
        break if page > datastore['MAXPAGE']
      end
    end

    # Save the results to this table
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'IP Results',
      'Indent'  => 1,
      'Columns' => ['IP', 'City', 'Country', 'Hostname']
    )

    # Organize results and put them into the table
    page = 1
    my_filter = datastore['FILTER']
    for i in page..tpages
      next if results[i].nil? or results[i]['matches'].nil?
      results[i]['matches'].each { |host|

        city = host['city'] || 'N/A'
        ip   = host['ip'] || 'N/A'
        port = host['port'] || ''
        country = host['country_name'] || 'N/A'
        hostname = host['hostnames'][0]
        data = host['data']

        if  ip =~ /#{my_filter}/ or
          city =~ /#{my_filter}/i or
          country =~ /#{my_filter}/i or
          hostname =~ /#{my_filter}/i or
          data =~ /#{my_filter}/i
          # Unfortunately we cannot display the banner properly,
          # because it messes with our output format
          tbl << ["#{ip}:#{port}", city, country, hostname]
        end
      }
    end

    #Show data and maybe save it if needed
    print_line("\n#{tbl.to_s}")

    report_note(
      :type => 'shodan',
      :data => tbl.to_csv
    ) if datastore['DATABASE']

    save_output(tbl.to_s) if not datastore['OUTFILE'].nil?
  end
end
