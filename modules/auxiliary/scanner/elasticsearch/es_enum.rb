##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'ElasticSearch Enum Utility',
      'Description' => 'Send a request to enumerate ElasticSearch indices',
      'Author'       => ['Silas Cutler <Silas.Cutler [at] BlackListThisDomain.com'],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(9200)
      ]
    )

  end

  def run_host(target_host)

    begin
      res = send_request_raw({
        'uri'     => '/_aliases',
        'method'  => 'GET',
        'version' => '1.0',
      }, 10)

    if res.nil?
      print_error("No response for #{target_host}")
      return nil
    end

    begin
      temp = JSON.parse(res.body)
    rescue JSON::ParserError
      print_error("Unable to parse JSON")
      return
    end


    if (res.code == 200)
      temp.each do |index|
          print_good("Index : " + index[0])
      end
    end

    if res and res.code == 200 and res.headers['Content-Type'] and res.body.length > 0
      path = store_loot("elasticsearch.enum.file", "text/plain", rhost, res.body, "ElasticSearch Enum Results")
      print_status("Results saved to #{path}")
    else
      print_error("Failed to save the result")
    end


    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
