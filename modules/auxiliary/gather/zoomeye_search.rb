##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex'
require 'net/https'
require 'uri'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'ZoomEye Search',
      'Description' => %q{
        The module use the ZoomEye API to search ZoomEye. ZoomEye is a search
        engine for cyberspace that lets the user find specific network
        components(ip, services, etc.). Site: https://www.zoomeye.org/api/doc
      },
      'Author'      => [ 'Nixawk' ],
      'License'     => MSF_LICENSE
      ))

      deregister_options('RHOST', 'DOMAIN', 'DigestAuthIIS', 'NTLM::SendLM',
            'NTLM::SendNTLM', 'VHOST', 'RPORT', 'NTLM::SendSPN', 'NTLM::UseLMKey',
            'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2', 'SSL')

      register_options(
        [
          OptString.new('ZOOMEYE_APIKEY', [true, 'The ZoomEye API Key']),
          OptString.new('ZOOMEYE_DORK', [true, 'The ZoomEye Dock']),
          OptEnum.new('RESOURCE', [true, 'ZoomEye Resource Type', 'host', ['host', 'web']]),
          OptInt.new('MAXPAGE', [true, 'Max amount of pages to collect', 1])
        ], self.class)
  end

  def dork_search(dork, resource, page, facet=['ip'])
    # param: dork
    #        ex: country:cn
    #        access https://www.zoomeye.org/search/dorks for more details.
    # param: page
    #        total page(s) number
    # param: resource
    #        set a search resource type, ex: [web, host]
    # param: facet
    #        ex: [app, device]
    #         A comma-separated list of properties to get summary information

    zoomeye_dork_api = "https://api.zoomeye.org/#{resource}/search"
    zoomeye_dork_api << "?query=" + Rex::Text.uri_encode(dork)
    zoomeye_dork_api << "&page=#{page}"
    zoomeye_dork_api << "&facet=facet"

    uri = URI.parse(zoomeye_dork_api)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri.request_uri)
    request['Authorization'] = "JWT #{datastore['ZOOMEYE_APIKEY']}"

    res = http.request(request)
    return 'server_response_error' unless res

    # Invalid Token, Not enough segments
    # Invalid Token, Signature has expired
    if res.body =~ /Invalid Token, /
      fail_with(Failure::BadConfig, '401 Unauthorized. Your ZOOMEYE_APIKEY is invalid')
    end

    ActiveSupport::JSON.decode(res.body)

  end

  def match_records?(records)
    records && records.key?('matches') ? true : false
  end

  def parse_host_records(records)
    records.each do |match|
      host = match['ip']
      port = match['portinfo']['port']

      report_service(:host => host, :port => port)
      print_good("Host: #{host} ,PORT: #{port}")
    end
  end

  def parse_web_records(records)
    records.each do |match|
      host = match['ip'][0]
      domains = match['domains']

      report_host(:host => host)
      print_good("Host: #{host}, Domains: #{domains}")
    end
  end

  def run
    dork = datastore['ZOOMEYE_DORK']
    resource = datastore['RESOURCE']
    page = 1
    maxpage = datastore['MAXPAGE']

    while page <= maxpage
      break if page > maxpage
      print_status("ZoomEye #{resource} Search: #{dork} - page: #{page}")
      results = dork_search(dork, resource, page) if dork
      break unless match_records?(results)

      matches = results['matches']
      if resource.include?('web')
        parse_web_records(matches)
      else
        parse_host_records(matches)
      end
      page += 1
    end
  end
end
