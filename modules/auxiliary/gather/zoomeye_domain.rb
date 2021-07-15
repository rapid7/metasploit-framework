##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Auxiliary::Report

    def initialize(info={})
        super(update_info(
                info,
                "name" => "ZoomEye Domain",
                "Description" => %q{
            The module use the ZoomEye API to search ZoomEye.ZoomEye is a cyberspace search engine,
            users can search for network devices using a browser.
            },
                'Author' => ['wh0am1i'],
                "References" => [
                  ["URL", "https://www.zoomeye.org/api/doc"],
                  ["URL", "https://github.com/knownsec/ZoomEye-python"]
                ],
                "License" => MSF_LICENSE
              ))

        register_options(
          [
            OptString.new('APIKEY', [true, 'The ZoomEye API KEY']),
            OptString.new('QUERY', [true, 'The ZoomEye dork']),
            OptInt.new('PAGE', [true, "Max amount of pages to collect", 1]),
            OptInt.new("SOURCE", [true, "Domain search type", 0]),
            OptBool.new('OUTFILE', [false, 'A filename to store ZoomEye search raw data']),
            OptBool.new('DATABSE', [false, 'Add search results to the database'])
          ]
        )
    end

    def zoomeye_resolvable?
        begin
            Rex::Socket.resolv_to_dotted("api.zoomeye.org")
        rescue RuntimeError, SocketError
            return false
        end
        true
    end

    def parse_domain_info(data)
        tab = Rex::Text::Table.new(
          "Header" => "Web Search Result",
          "Indent" => 1,
          "Columns" => ['IP', 'NAME', 'TIMESTAMP']
        )
        data.each do |item|
            name = item['name']
            timestamp = item['timestamp']
            ip = item['ip']

            tab << [ip, name, timestamp]

            report_host(:host => ip,
                        :name => name,
                        :comments => 'Added from ZoomEye Domain Search',
                        ) if datastore['DATABASE']
        end
        print_line("#{tab}")
    end

    def save_raw_data(query, data, page)
        filename = query.gsub(/[^a-zA-Z ]/,'_')
        ::File.open("#{filename}_#{page}.json", "wb") do |f|
            f.write(ActiveSupport::JSON.encode(data))
        end
    end

    def domain_search(apikey, query, page, s_type)
        request = Rex::Proto::Http::Client.new('api.zoomeye.org', 443, {}, true)
        request.connect

        begin
            response = request.request_cgi({
                                             "uri" => "/domain/search",
                                             "method" => 'GET',
                                             "headers" => {"API-KEY" => "#{apikey}"},
                                             "vars_get" => {
                                               "q" => query,
                                               "page" => page,
                                               "type" => s_type
                                             }
                                           })
            result = request.send_recv(response)
        rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
            print_error("HTTP Connection Failed")
        end

        unless result
            print_error("Server Error")
        end

        result_json = result.get_json_document

        if result_json.key?('error')
            fail_with(Failure::BadConfig, "401 Unauthorized. Your ZoomEye API Key is invalid")
        end
        return result_json
    end

    def run
        unless zoomeye_resolvable?
            print_error("Unable to resolve api.zoomeye.org")
            return
        end
        query = datastore['QUERY']
        apikey = datastore['APIKEY']
        page = datastore['PAGE']
        s_type = datastore['SOURCE']
        current_page = 1
        all_data = []
        while current_page <= page
            results = domain_search(apikey, query, current_page, s_type)

            save_raw_data(query, results, current_page) if datastore['OUTFILE']
            all_data.append(results)
            current_page += 1
        end
        all_data.each do |match|
            parse_domain_info(match['list'])
        end
        print_status("Total: #{results['total']}, Current #{page * 30} ")
    end
end