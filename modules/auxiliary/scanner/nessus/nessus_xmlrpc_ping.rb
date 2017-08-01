##
# nessus_xmlrpc_ping.rb
##

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
      'Name'           => 'Nessus XMLRPC Interface Ping Utility',
      'Description'    => %q{
        This module simply attempts to find and check
        for Nessus XMLRPC interface.'
      },
      'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true }
    )

    register_options(
      [
        Opt::RPORT(8834),
        OptInt.new('THREADS', [true, "The number of concurrent threads", 25]),
        OptString.new('URI', [true, "URI for Nessus XMLRPC. Default is /", "/"])
      ])
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
    if not (res.code == 200 or res.code ==302)
      vprint_error("HTTP Response was not 200/302")
      return
    end
    if res.headers['Server'] =~ /NessusWWW/
      print_good("SUCCESS. '#{ip}' : '#{datastore['RPORT']}'")
      report_service(
        :host => ip,
        :port => datastore['RPORT'],
        :name => "nessus-xmlrpc",
        :info => 'Nessus XMLRPC',
        :state => 'open'
      )
    else
      vprint_error("Wrong HTTP Server header: #{res.headers['Server'] || ''}")
    end

  end
end
