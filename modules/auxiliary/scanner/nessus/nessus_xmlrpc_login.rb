##
# nessus_xmlrpc_login.rb
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'Nessus XMLRPC Interface Login Utility',
            'Description'    => %q{
              This module simply attempts to login to a Nessus XMLRPC interface using a
              specific user/pass.
            },
            'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
            'License'        => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(8834),
        OptString.new('URI', [true, "URI for Nessus XMLRPC login. Default is /login", "/login"]),
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
      vprint_error("#{datastore['URI']} - #{e}")
      return
    end

    if not res
      vprint_error("#{datastore['URI']} - No response")
      return
    end
    if res.code != 403
      vprint_error("Authorization not requested")
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def do_login(user='nessus', pass='nessus')
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    headers = {}

    begin
      res = send_request_cgi({
        'encode'    => true,
        'uri'       => datastore['URI'],
        'method'    => 'POST',
        'headers'   => headers,
        'vars_post' => {
          'login'    => user,
          'password' => pass
        }
      }, 25)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("Connection timed out, Aborting")
      return :abort
    end

    if res.code != 200
      vprint_error("FAILED LOGIN. '#{user}' : '#{pass}'")
      return :skip_pass
    end

    if res.code == 200
      if res.body =~ /<status>OK<\/status>/
        print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

        report_hash = {
          :host   => datastore['RHOST'],
          :port   => datastore['RPORT'],
          :sname  => 'nessus-xmlrpc',
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
