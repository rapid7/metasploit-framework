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
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Vuln Scanner',
      'Description'	=> %q{
        This module identifies common vulnerable files or cgis.
      },
      'Author' 		=> [ 'et' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true, "Original test path", '/']),
        OptPath.new('VULNCSV',[ true, "Path of vulnerabilities csv file to use" ])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true,  "The expected http code for non existant files", 404]),
        OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
            File.join(Msf::Config.data_directory, "wmap", "wmap_404s.txt")
          ]
        ),
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ]),
        OptBool.new('ForceCode', [ false, "Force detection using HTTP code", false ]),
        OptInt.new('TestThreads', [ true, "Number of test threads", 25])
      ], self.class)

  end

  # Modify to true if you have sqlmap installed.
  def wmap_enabled
    false
  end

  def run_host(ip)
    conn = false
    usecode = datastore['ForceCode']

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    nt = datastore['TestThreads'].to_i
    nt = 1 if nt == 0

    dm = datastore['NoDetailMessages']

    queue = []

    File.open(datastore['VULNCSV'], 'rb').each do |testf|
      queue << testf.strip
    end

    #
    # Detect error code
    #
    ecode = datastore['ErrorCode'].to_i
    begin
      randfile = Rex::Text.rand_text_alpha(5).chomp

      res = send_request_cgi({
        'uri'  		=>  tpath+randfile,
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


    while(not queue.empty?)
      t = []
      1.upto(nt) do
        t << framework.threads.spawn("Module(#{self.refname})-#{rhost}", false, queue.shift) do |testf|
          Thread.current.kill if not testf

          testarr = []
          testfvuln = ""
          testmesg = ""
          testnote = ""
          foundstr = false

          testarr = testf.split(',')

          testfvuln = testarr[0].to_s
          testmesg = testarr[1].to_s
          testnote = testarr[2].to_s

          res = send_request_cgi({
            'uri'  		=>  tpath+testfvuln,
            'method'   	=> 'GET',
            'ctype'		=> 'text/plain'
          }, 20)

          if res.nil?
            print_error("Connection timed out")
            return
          end

          if testmesg.empty? or usecode
            if (res.code.to_i == ecode) or (emesg and res.body.index(emesg))
              if dm == false
                print_status("NOT Found #{wmap_base_url}#{tpath}#{testfvuln}  #{res.code.to_i}")
              end
            else
              if res.code.to_i == 400  and ecode != 400
                print_error("Server returned an error code. #{wmap_base_url}#{tpath}#{testfvuln} #{res.code.to_i}")
              else
                print_status("FOUND #{wmap_base_url}#{tpath}#{testfvuln} [#{res.code.to_i}] #{testnote}")

                report_note(
                  :host	=> ip,
                  :proto => 'tcp',
                  :sname => (ssl ? 'https' : 'http'),
                  :port	=> rport,
                  :type	=> 'FILE',
                  :data	=> "#{tpath}#{testfvuln} Code: #{res.code}"
                )
              end
            end
          else
            if res and res.body.include?(testmesg)
              print_status("FOUND #{wmap_base_url}#{tpath}#{testfvuln} [#{res.code.to_i}] #{testnote}")

              report_note(
                  :host	=> ip,
                  :proto => 'tcp',
                  :sname => (ssl ? 'https' : 'http'),
                  :port	=> rport,
                  :type	=> 'FILE',
                  :data	=> "#{tpath}#{testfvuln} Code: #{res.code}"
              )
            else
              if dm == false
                print_status("NOT Found #{wmap_base_url}#{tpath}#{testfvuln}  #{res.code.to_i}")
              end
            end
          end
        end
      end
      t.map{|x| x.join }
    end
  end
end
