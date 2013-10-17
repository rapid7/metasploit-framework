##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
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
      'Name'   		=> 'HTTP Interesting File Scanner',
      'Description'	=> %q{
        This module identifies the existence of interesting files
        in a given directory path.
      },
      'Author' 		=> [ 'et' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path  to identify files", '/']),
        OptString.new('EXT', [ false, "Append file extension to use", '']),
        OptPath.new('DICTIONARY',   [ false, "Path of word dictionary to use",
            File.join(Msf::Config.install_root, "data", "wmap", "wmap_files.txt")
          ]
        )
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true,  "The expected http code for non existant files", 404]),
        OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
            File.join(Msf::Config.install_root, "data", "wmap", "wmap_404s.txt")
          ]
        ),
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ]),
        OptInt.new('TestThreads', [ true, "Number of test threads", 25])
      ], self.class)

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
      '.ini',
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

    conn = false

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    nt = datastore['TestThreads'].to_i
    nt = 1 if nt == 0

    dm = datastore['NoDetailMessages']



    extensions << datastore['EXT']

    extensions.each do |ext|
      queue = []

      File.open(datastore['DICTIONARY'], 'rb').each do |testf|
        queue << testf.strip
      end

      #
      # Detect error code
      #
      ecode = datastore['ErrorCode'].to_i
      begin
        randfile = Rex::Text.rand_text_alpha(5).chomp

        res = send_request_cgi({
          'uri'  		=>  tpath+randfile+ext,
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
            print_status("Using first 256 bytes of the response as 404 string for files with extension #{ext}")
            emesg = res.body[0,256]
          else
            print_status("Using custom 404 string of '#{emesg}'")
          end
        else
          ecode = tcode
          print_status("Using code '#{ecode}' as not found for files with extension #{ext}")
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

            testfext = testf.chomp + ext
            res = send_request_cgi({
              'uri'  		=>  tpath+testfext,
              'method'   	=> 'GET',
              'ctype'		=> 'text/plain'
            }, 20)

            if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
              if dm == false
                print_status("NOT Found #{wmap_base_url}#{tpath}#{testfext}  #{res.code.to_i}")
                #blah
              end
            else
              if res.code.to_i == 400  and ecode != 400
                print_error("Server returned an error code. #{wmap_base_url}#{tpath}#{testfext} #{res.code.to_i}")
              else
                print_status("Found #{wmap_base_url}#{tpath}#{testfext} #{res.code.to_i}")

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

              end
            end
          end
        end
        t.map{|x| x.join }
      end
    end
  end
end
