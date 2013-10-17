##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'
require 'pathname'



class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanFile
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP File Extension Scanner',
      'Description'	=> %q{
        This module identifies the existence of additional files
        by modifying the extension of an existing file.

      },
      'Author' 		=> [ 'et [at] cyberspace.org' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path/file to identify additional files", '/default.asp']),
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('ErrorCode', [ true,  "The expected http code for non existant files", 404]),
        OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
            File.join(Msf::Config.install_root, "data", "wmap", "wmap_404s.txt")
          ]
        ),
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ])
      ], self.class)


  end

  def run_host(ip)

    conn = false

    dm = datastore['NoDetailMessages']

    extensions= [
      '.bak',
      '.txt',
      '.tmp',
      '.old',
      '.htm',
      '.ini',
      '.cfg',
      '.html',
      '.php',
      '.temp',
      '.tmp',
      '.java',
      '.doc',
      '.log',
      '.xml'
    ]


    tpathfile = Pathname.new(datastore['PATH'])
    oldext = tpathfile.extname
    tpathnoext = tpathfile.to_s[0..(datastore['PATH'].rindex(oldext)-1)]

    #print_status ("Old extension: #{oldext}")

    extensions.each { |testext|

    if oldext == testext
      next
    end

    #print_status ("Test extension: #{testext}")



      #
      # Detect error code. This module is a special case as each extension
      # usually is handled diferently by the server with different error codes
      #
      ecode = datastore['ErrorCode'].to_i
      begin
        randchars = Rex::Text.rand_text_alpha(3).chomp
        tpath = tpathnoext+randchars+testext

        res = send_request_cgi({
          'uri'  		=>  tpath,
          'method'   	=> 'GET',
          'ctype'		=> 'text/html'
        }, 20)

        return if not res

        tcode = res.code.to_i

        emesg = ""

        # Look for a string we can signature on as well
        if(tcode >= 200 and tcode <= 299)

          File.open(datastore['HTTP404Sigs'], 'rb').each do |str|
            if(res.body.index(str))
              emesg = str
              break
            end
          end

          if(not emesg)
            print_status("Using first 256 bytes of the response as 404 string for #{testext} files.")
            emesg = res.body[0,256]
          else
            print_status("Using custom 404 string of '#{emesg}' for #{testext} files.")
          end
        else
          ecode = tcode
          print_status("Using code '#{ecode}' as not found for #{testext} files.")
        end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        conn = false
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

      #if not conn return

      begin
        tpath = tpathnoext+testext
          res = send_request_cgi({
            'uri'  		=>  tpath,
            'method'   	=> 'GET',
            'ctype'		=> 'text/plain'
        }, 20)

        if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
          if dm == false
            print_status("NOT Found #{wmap_base_url}#{tpath}  #{res.code.to_i}")
            #blah
          end
        else
          if res.code.to_i == 400  and ecode != 400
            print_error("Server returned an error code. #{wmap_base_url}#{tpath} #{res.code.to_i}")
          else
            print_status("Found #{wmap_base_url}#{tpath}")

            report_web_vuln(
              :host	=> ip,
              :port	=> rport,
              :vhost  => vhost,
              :ssl    => ssl,
              :path	=> tpath,
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
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
      end
    }

  end

end
