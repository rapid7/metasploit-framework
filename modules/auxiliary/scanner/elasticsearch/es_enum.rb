##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'ElasticSearch Enum Utility',
      'Description'  => %q{ Send a request to enumerate ElasticSearch indices},
      'Author'         =>
        [
          'Silas Cutler <Silas.Cutler [at] BlackListThisDomain.com>'
        ],
      'License'      => MSF_LICENSE
    ))    
    
    register_options(
      [
        Opt::RPORT(9200)
      ], self.class)
  end

  def run_host(ip)
    begin
      res = send_request_raw({
        'uri'     => '/_aliases',
        'method'  => 'GET',
      })

    begin
      json_body = JSON.parse(res.body)
    rescue JSON::ParserError
      print_error("Unable to parse JSON")
      return
    end

    if res and res.code == 200  and res.body.length > 0
      json_body.each do |index|
          print_good("Index : " + index[0])
      end

      path = store_loot("elasticsearch.enum.file", "text/plain", ip, res.body, "ElasticSearch Enum Results")
      print_good("Results saved to #{path}")
    else
      print_error("Failed to save the result")
    end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable
    end
  end
end
