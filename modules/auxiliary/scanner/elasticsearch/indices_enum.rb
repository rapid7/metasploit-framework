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
      'Name'         => 'ElasticSearch Indices Enumeration Utility',
      'Description'  => %q{
        This module enumerates ElasticSearch Indices. It uses the REST API
        in order to make it.
      },
      'Author'         =>
        [
          'Silas Cutler <Silas.Cutler[at]BlackListThisDomain.com>'
        ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(9200)
      ], self.class)
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    vprint_status("#{peer} - Querying indices...")
    begin
      res = send_request_raw({
        'uri'     => '/_aliases',
        'method'  => 'GET',
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable
      vprint_error("#{peer} - Unable to establish connection")
      return
    end

    if res && res.code == 200 && res.body.length > 0
      begin
        json_body = JSON.parse(res.body)
      rescue JSON::ParserError
        vprint_error("#{peer} - Unable to parse JSON")
        return
      end
    else
      vprint_error("#{peer} - Timeout or unexpected response...")
      return
    end

    report_service(
      :host  => rhost,
      :port  => rport,
      :proto => 'tcp',
      :name  => 'elasticsearch'
    )

    indices = []

    json_body.each do |index|
      indices.push(index[0])
      report_note(
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :type  => "elasticsearch.index",
        :data  => index[0],
        :update => :unique_data
      )
    end

    if indices.length > 0
      print_good("#{peer} - ElasticSearch Indices found: #{indices.join(", ")}")
    end

  end

end
