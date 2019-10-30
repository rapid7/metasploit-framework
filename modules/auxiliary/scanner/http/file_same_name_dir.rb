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
      'Name'   		=> 'HTTP File Same Name Directory Scanner',
      'Description'	=> %q{
        This module identifies the existence of files
        in a given directory path named as the same name of the
        directory.

        Only works if PATH is different than '/'.
      },
      'Author' 		=> [ 'et [at] metasploit.com' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The directory path  to identify files", '/']),
        OptString.new('EXT', [ true, "File extension to use", '.aspx']),

      ])

  end

  def run_host(ip)
    extensions = [
      '.null',
      '.backup',
      '.bak',
      '.c',
      '.cfg',
      '.class',
      '.copy',
      '.conf',
      '.exe',
      '.html',
      '.htm',
      '.log',
      '.old',
      '.orig',
      '.php',
      '.tar',
      '.tar.gz',
      '.tgz',
      '.tmp',
      '.temp',
      '.txt',
      '.zip',
      '~',
      ''
    ]

    tpath = normalize_uri(datastore['PATH'])

    if tpath.eql? "/"||""
      print_error("Blank or default PATH set.");
      return
    end

    if tpath[-1,1] != '/'
      tpath += '/'
    end

    testf = tpath.split('/').last

    extensions << datastore['EXT']

    extensions.each { |ext|
      begin
        testfext = testf.chomp + ext
        res = send_request_cgi({
          'uri'  		=>  tpath+testfext,
          'method'   	=> 'GET',
          'ctype'		=> 'text/plain'
        }, 20)

        if (res and res.code >= 200 and res.code < 300)
          print_good("Found #{wmap_base_url}#{tpath}#{testfext}")

          report_web_vuln(
            :host	=> ip,
            :port	=> rport,
            :vhost  => vhost,
            :ssl    => ssl,
            :path	=> "#{tpath}#{testfext}",
            :method => 'GET',
            :pname  => "",
            :proof  => "Res code: #{res.code.to_s}",
            :risk   => 0,
            :confidence   => 100,
            :category     => 'file',
            :description  => 'File found.',
            :name   => 'file'
          )

        else
          vprint_status("NOT Found #{wmap_base_url}#{tpath}#{testfext}")
        end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

    }

  end
end
