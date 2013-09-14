##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'enumerable'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Directory Brute Force Scanner',
      'Description'	=> %q{
        This module identifies the existence of interesting directories by brute forcing the name
        in a given directory path.

      },
      'Author' 		=> [ 'et' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path to identify directories", '/']),
        OptString.new('FORMAT', [ true,  "The expected directory format (a alpha, d digit, A upperalpha)", 'a,aa,aaa'])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true,  "The expected http code for non existant directories", 404]),
        OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
            File.join(Msf::Config.install_root, "data", "wmap", "wmap_404s.txt")
          ]
        ),
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ]),
        OptInt.new('TestThreads', [ true, "Number of test threads", 25])
      ], self.class)

  end

  def wmap_enabled
    true
  end

  def run_host(ip)

    conn = false

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    dm = datastore['NoDetailMessages']

    # You may add more extensions in the extens array
    extens = ["/"]

    # You may add multiple formats in the array
    forma = []
    forma = datastore['FORMAT'].split(',')

    ecode = datastore['ErrorCode'].to_i
    extens.each do |exte|

      #
      # Detect error code
      #
      ecode = datastore['ErrorCode'].to_i
      begin
        randdir = Rex::Text.rand_text_alpha(5).chomp
        randdir << exte
        res = send_request_cgi({
          'uri'  		=>  tpath+randdir,
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

      forma.each do |f|

        numb = []
        f.scan(/./) { |c|
          case c
          when 'a'
            numb << ('a'..'z')
          when 'd'
            numb << ('0'..'9')
          when 'A'
            numb << ('A'..'Z')
      # These dont actually work
      #		when 'N'
      #			numb << ('A'..'Z')+('0'..'9')
      #		when 'n'
      #			numb << ('a'..'z')+('0'..'9')
          else
            print_error("Format string error")
            return
          end
        }

        #exte.scan(/./) { |c|
        #	numb << "#{c}"
        #}

        Enumerable.cart(*numb).each {|testd|

          strdir = testd.join

          begin
            teststr = tpath+strdir
            teststr << exte

            res = send_request_cgi({
              'uri'  		=>  teststr,
              'method'   	=> 'GET',
              'ctype'		=> 'text/plain'
            }, 5)

            if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
              if dm == false
                print_status("NOT Found #{wmap_base_url}#{teststr}  #{res.code.to_i}")
                #blah
              end
            else
              if res.code.to_i == 400  and ecode != 400
                print_error("Server returned an error code. #{wmap_base_url}#{teststr} #{res.code.to_i}")
              else
                print_status("Found #{wmap_base_url}#{teststr} #{res.code.to_i}")

                report_web_vuln(
                  :host	=> ip,
                  :port	=> rport,
                  :vhost  => vhost,
                  :ssl    => ssl,
                  :path	=> "#{teststr}",
                  :method => 'GET',
                  :pname  => "",
                  :proof  => "Res code: #{res.code.to_s}",
                  :risk   => 0,
                  :confidence   => 100,
                  :category     => 'directory',
                  :description  => 'Directory found.',
                  :name   => 'directory'
                  )

              end
            end

          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          rescue ::Timeout::Error, ::Errno::EPIPE
          end

        }
      end
    end
  end
end
