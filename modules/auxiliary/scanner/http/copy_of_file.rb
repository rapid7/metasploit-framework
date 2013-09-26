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
  include Msf::Auxiliary::WmapScanFile
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Copy File Scanner',
      'Description'	=> %q{
        This module identifies the existence of possible copies
        of a specific file in a given path.
      },
      'Author' 		=> [ 'et [at] cyberspace.org' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path/file to identify copies", '/index.asp'])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true, "Error code for non existent directory", 404]),
        OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
            File.join(Msf::Config.data_directory, "wmap", "wmap_404s.txt")
          ]
        ),
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ])
      ], self.class)

  end

  def run_host(ip)
    conn = true
    ecode = nil
    emesg = nil

    ecode = datastore['ErrorCode'].to_i
    dm = datastore['NoDetailMessages']

    # Required to calculate error code for each case as special charcters amd spaces
    # trigger different responses

    prestr = [
            'Copy_(1)_of_',
            'Copy_(2)_of_',
            'Copy of ',
            'Copy_of_',
            'Copy_',
            'Copy',
            '_'
          ]


    tpathf = normalize_uri(datastore['PATH'])
    testf = tpathf.split('/').last


    if testf
      prestr.each do |pre|
        #
        # Detect error code
        #
        begin
          randfile = Rex::Text.rand_text_alpha(5).chomp

          filec = tpathf.sub(testf,pre + randfile + testf)

          res = send_request_cgi({
            'uri'  		=>  filec,
            'method'   	=> 'GET',
            'ctype'		=> 'text/html'
          }, 20)

          return if not res

          tcode = res.code.to_i


          # Look for a string we can signature on as well
          if(tcode >= 200 and tcode <= 299)

            File.open(datastore['HTTP404Sigs'], 'rb').each do |str|
              if(res.body.index(str))
                emesg = str
                break
              end
            end

            if(not emesg)
              print_status("Using first 256 bytes of the response as 404 string")
              emesg = res.body[0,256]
            else
              print_status("Using custom 404 string of '#{emesg}'")
            end
          else
            ecode = tcode
            print_status("Using code '#{ecode}' as not found.")
          end

        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          conn = false
        rescue ::Timeout::Error, ::Errno::EPIPE
        end

        return if not conn

        filec = tpathf.sub(testf,pre + testf)

        begin
          res = send_request_cgi({
            'uri'  		=>  filec,
            'method'   	=> 'GET',
            'ctype'		=> 'text/plain'
          }, 20)

          if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
            if dm == false
              print_status("NOT Found #{filec} #{res.code} [#{wmap_target_host}] [#{res.code.to_i}]")
            end
          else
            if ecode != 400 and res.code.to_i == 400
              print_error("[#{wmap_target_host}] Server returned a 400 error on #{wmap_base_url}#{filec} [#{res.code.to_i}]")
            else
              print_status("[#{wmap_target_host}] Found #{wmap_base_url}#{filec} [#{res.code.to_i}]")

              report_web_vuln(
                :host	=> ip,
                :port	=> rport,
                :vhost  => vhost,
                :ssl    => ssl,
                :path	=> "#{filec}",
                :method => 'GET',
                :pname  => "",
                :proof  => "Res code: #{res.code.to_s}",
                :risk   => 0,
                :confidence   => 100,
                :category     => 'file',
                :description  => 'Copy file found.',
                :name   => 'copy of file'
              )
            end
          end

        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        rescue ::Timeout::Error, ::Errno::EPIPE
        end
      end
    end
  end
end
