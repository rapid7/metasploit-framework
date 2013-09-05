##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'
require 'uri'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanUniqueQuery
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Ruby On Rails Attributes Mass Assignment Scanner',
      'Description'   => %q{
        This module scans Ruby On Rails sites for
        models with attributes not protected by attr_protected or attr_accessible.
        After attempting to assign a non-existent field, the default rails with
        active_record setup will raise an ActiveRecord::UnknownAttributeError
        exeption, and reply with HTTP code 500.
      },

      'References'     =>
        [
          [ 'URL', 'http://guides.rubyonrails.org/security.html#mass-assignment' ]
        ],
      'Author'       => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        OptEnum.new('METHOD', [true, 'HTTP Method', 'POST', ['GET', 'POST'] ]),
        OptString.new('PATH', [ true, "The path to test mass assignment", '/users/1']),
        OptString.new('QUERY', [ false, "HTTP URI Query", nil]),
        OptString.new('DATA', [ false, "HTTP Body Data", '']),
        OptString.new('COOKIE',[ false, "HTTP Cookies", ''])
      ], self.class)
  end

  def run_host(ip)
    case datastore['METHOD']
    when 'POST'
      parsed_data = queryparse(URI.unescape(datastore['DATA']))
    when 'GET'
      parsed_data = queryparse(URI.unescape(datastore['QUERY']))
    end
    data_base_params = get_base_params(parsed_data)

    if data_base_params.blank?
      vprint_error("#{ip} - Non-standart rails params schema (maybe not a RoR website)")
      return
    end

    check_data(ip, parsed_data, data_base_params)
  end

  def get_base_params(parsed_query_string)
    base_params_names = []
    parsed_query_string.each do |key, val|
      key.gsub(/(.*)\[(\w*)\]$/) do
        base_params_names << $1
      end
    end
    return base_params_names.uniq
  end

  def check_data(ip, parsed_data, base_params)
    base_params.each do |param|
      query = parsed_data.dup
      test_param = { param + "[#{Rex::Text.rand_text_alpha(10)}]" => Rex::Text.rand_text_alpha(10) }
      query.merge!(test_param)

      resp = send_request_cgi({
        'uri'       => normalize_uri(datastore['PATH']),
        'vars_get'  => datastore['METHOD'] == 'POST' ? queryparse(datastore['QUERY'].to_s) : query,
        'method'    => datastore['METHOD'],
        'ctype'     => 'application/x-www-form-urlencoded',
        'cookie'    => datastore['COOKIE'],
        'data'      => datastore['METHOD'] == 'POST' ? query.to_query : datastore['DATA']
      }, 20)

      if resp and resp.code == 500
        print_good("#{ip} - Possible attributes mass assignment in attribute #{param}[...] at #{datastore['PATH']}")
        report_web_vuln(
          :host   => rhost,
          :port   => rport,
          :vhost  => vhost,
          :ssl    => ssl,
          :path   => "#{datastore['PATH']}",
          :method => datastore['METHOD'],
          :pname  => param,
          :proof  => "rails mass assignment",
          :risk   => 2,
          :confidence   => 80,
          :category     => 'Rails',
          :description  => "Possible attributes mass assignment in attribute #{param}[...]",
          :name   => 'Ruby On Rails Attributes Mass Assignment'
        )
      end
    end
  end
end
