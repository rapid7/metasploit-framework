##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'enumerable'

class MetasploitModule < Msf::Auxiliary
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
        OptString.new('FORMAT', [ true,  "The expected directory format (a alpha, d digit, A upperalpha)", 'a,aa,aaa']),
        OptInt.new('TIMEOUT', [true, 'The socket connect/read timeout in seconds', 20]),
        OptInt.new('DELAY', [true, "The delay between connections, per thread, in milliseconds", 0]),
        OptInt.new('JITTER', [true, "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.", 0]),
      ])

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true,  "The expected http code for non existent directories", 404]),
        OptPath.new('HTTP404Sigs', [ false, "Path of 404 signatures to use",
          File.join(Msf::Config.data_directory, "wmap", "wmap_404s.txt")
        ]),
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ]),
        OptInt.new('TestThreads', [ true, "Number of test threads", 25])
      ])
  end

  def wmap_enabled
    true
  end

  def run_host(ip)

    conn = false

    timeout = datastore['TIMEOUT']

    delay_value = datastore['DELAY'].to_i
    if delay_value < 0
      raise Msf::OptionValidateError.new(['DELAY'])
    end

    jitter_value = datastore['JITTER'].to_i
    if jitter_value < 0
      raise Msf::OptionValidateError.new(['JITTER'])
    end

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    vhost = datastore['VHOST'] || datastore['RHOST']

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
          'uri'    =>  tpath+randdir,
          'method' => 'GET',
          'ctype'  => 'text/html'
        }, timeout)

        return if not res

        tcode = res.code.to_i

        # Look for a string we can signature on as well
        if(tcode >= 200 and tcode <= 299)
          emesg = nil
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

            # Add the delay based on JITTER and DELAY if needs be
            add_delay_jitter(delay_value,jitter_value)

            vprint_status("Try... #{wmap_base_url}#{teststr} (#{vhost})")

            res = send_request_cgi({
              'uri'    =>  teststr,
              'method' => 'GET',
              'ctype'  => 'text/plain'
            }, timeout)

            if (not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
              if dm == false
                print_status("NOT Found #{wmap_base_url}#{teststr} #{res.code.to_i}")
                #blah
              end
            else
              if res.code.to_i == 400  and ecode != 400
                print_error("Server returned an error code. #{wmap_base_url}#{teststr} #{res.code.to_i}")
              else
                print_good("Found #{wmap_base_url}#{teststr} #{res.code.to_i}")

                report_web_vuln({
                  :host         => rhost,
                  :port         => rport,
                  :vhost        => vhost,
                  :ssl          => ssl,
                  :path         => "#{teststr}",
                  :method       => 'GET',
                  :pname        => "",
                  :proof        => "Res code: #{res.code.to_s}",
                  :risk         => 0,
                  :confidence   => 100,
                  :category     => 'directory',
                  :description  => 'Directory found.',
                  :name         => 'directory'
                })

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
