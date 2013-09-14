##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Previous Directory File Scanner',
      'Description'	=> %q{
        This module identifies files in the first parent directory with same name as
        the given directory path. Example: Test /backup/files/ will look for the
        following files /backup/files.ext .
      },
      'Author' 		=> [ 'et [at] metasploit.com' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path. The default value will not work.", '/']),
        OptString.new('EXT', [ true,  "Extension to include.", '.aspx']),
      ], self.class)

  end

  def run_host(ip)
    extensions = [
      '.null',
      '.backup',
      '.bak',
      '.c',
      '.class',
      '.copy',
      '.conf',
      '.exe',
      '.html',
      '.htm',
      '.jar',
      '.log',
      '.old',
      '.orig',
      '.o',
      '.php',
      '.tar',
      '.tar.gz',
      '.tgz',
      '.temp',
      '.tmp',
      '.txt',
      '.zip',
      '~'
    ]

    tpath = normalize_uri(datastore['PATH'])

    if tpath.eql? "/"||""
      print_error("Blank or default PATH set.");
      return
    end

    if tpath[-1,1] != '/'
      tpath += '/'
    end

    extensions << datastore['EXT']

    extensions.each { |ext|
      begin
        testf = tpath.chop+ext

        res = send_request_cgi({
          'uri'  		=>  testf,
          'method'   	=> 'GET',
          'ctype'		=> 'text/plain'
        }, 20)

        if (res and res.code >= 200 and res.code < 300)
          print_status("Found #{wmap_base_url}#{testf}")

          report_web_vuln(
            :host	=> ip,
            :port	=> rport,
            :vhost  => vhost,
            :ssl    => ssl,
            :path	=> testf,
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
          vprint_status("NOT Found #{wmap_base_url}#{testf}")
        end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

    }

  end
end
