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
          'name' => 'ZoomEye Domain',
          'Description' => %q{
            The module use the ZoomEye API to search ZoomEye.ZoomEye is a cyberspace search engine,
            users can search for network devices using a browser.
          },
          'Author' => ['wh0am1i'],
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
        OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1]),
        OptInt.new('SOURCE', [true, 'Domain search type', 0]),
        OptBool.new('OUTFILE', [false, 'A filename to store ZoomEye search raw data']),
        OptBool.new('DATABASE', [false, 'Add search results to the database'])
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

  def parse_domain_info(data)
    tab = Rex::Text::Table.new(
      'Header' => 'Web Search Result',
      'Indent' => 1,
      'Columns' => ['IP', 'NAME', 'TIMESTAMP']
    )
    data.each do |match|
      match['list'].each do |item|
        name = item['name']
        timestamp = item['timestamp']
        ip = item['ip']

        tab << [ip, name, timestamp]

        next unless datastore['DATABASE']

        report_host(host: ip,
                    name: name,
                    comments: 'Added from ZoomEye Domain Search')
      end
      print_line(tab.to_s)
    end
  end

  def save_raw_data(query, data)
    filename = query.gsub(/[^a-zA-Z ]/, '_')
    ::File.open("#{filename}.json", 'wb') do |f|
      f.write(ActiveSupport::JSON.encode(data))
      print_status("Save ZoomEye Result in #{filename}.json")
    end
  end

  def domain_search(apikey, query, page, s_type)
    res = send_request_cgi({
      'method' => 'GET',
      'rhost' => 'api.zoomeye.org',
      'rport' => 443,
      'uri' => '/domain/search',
      'SSL' => true,
      'headers' => { 'API-KEY' => apikey.to_s },
      'vars_get' => {
        'q' => query,
        'page' => page,
        'type' => s_type
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

  def run
    unless zoomeye_resolvable?
      print_error('Unable to resolve api.zoomeye.org')
      return
    end
    query = datastore['ZOOMEYE_DORK']
    apikey = datastore['APIKEY']
    page = datastore['MAXPAGE']
    s_type = datastore['SOURCE']
    all_data = []
    1.upto(datastore['MAXPAGE']) do |current_page|
      results = domain_search(apikey, query, current_page, s_type)
      all_data.append(results)
    end

    parse_domain_info(all_data)

    save_raw_data(query, all_data) if datastore['OUTFILE']
    print_status("Total: #{all_data[0]['total']}, Current #{page * 30}")
  end
end
