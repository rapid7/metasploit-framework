##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Directory Listing Scanner',
      'Description'	=> %q{
        This module identifies directory listing vulnerabilities
        in a given directory path.
      },
      'Author' 		=> [ 'et' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path to identify directory listing", '/']),
      ])

  end

  def run_host(ip)

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    begin
      res = send_request_cgi({
        'uri'  		=>  tpath,
        'method'   	=> 'GET',
        'ctype'		=> 'text/plain'
        }, 20)

      if (res and res.code >= 200 and res.code < 300)
        if res.to_s.include? "<title>Index of /" and res.to_s.include? "<h1>Index of /"
          print_good("Found Directory Listing #{wmap_base_url}#{tpath}")

          report_web_vuln(
            :host	=> ip,
            :port	=> rport,
            :vhost  => vhost,
            :ssl    => ssl,
            :path	=> "#{tpath}",
            :method => 'GET',
            :pname  => "",
            :proof  => "Res code: #{res.code.to_s}",
            :risk   => 0,
            :confidence   => 100,
            :category     => 'directory',
            :description  => 'Directory found allowing listing of its contents.',
            :name   => 'directory listing'
          )

        end

        if res.to_s.include? "[To Parent Directory]</A>" and res.to_s.include? "#{tpath}</H1><hr>"
          print_good("Found Directory Listing #{wmap_base_url}#{tpath}")

          report_web_vuln(
            :host	=> ip,
            :port	=> rport,
            :vhost  => vhost,
            :ssl    => ssl,
            :path	=> "#{tpath}",
            :method => 'GET',
            :pname  => "",
            :proof  => "Res code: #{res.code.to_s}",
            :risk   => 0,
            :confidence   => 100,
            :category     => 'directory',
            :description  => 'Directory found allowing listing of its contents.',
            :name   => 'directory listing'
          )

        end

      else
        vprint_status("NOT Vulnerable to directory listing #{wmap_base_url}#{tpath}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
