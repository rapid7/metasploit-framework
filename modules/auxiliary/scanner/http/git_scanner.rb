##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP Git Scanner',
      'Description' => 'Detect git directories and files and analize its content.',
      'Author'       => ['t0nyhj'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to .git directory", '/'])#,
        #OptBool.new('GET_SOURCE', [ false, "Attempt to obtain file source code", true ]),
        #OptBool.new('SHOW_SOURCE', [ false, "Show source code", true ])

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

  def run_host(target_host)
    conn = true
    ecode = nil
    emesg = nil

    word1 = 'core'
    word2 = 'remote'
    word3 = 'branch'

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    ecode = datastore['ErrorCode'].to_i
    vhost = datastore['VHOST'] || wmap_target_host

    #
    # Detect error code
    #
    begin
      randdir = Rex::Text.rand_text_alpha(5).chomp + '/'
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
          #print_status("Using first 256 bytes of the response as 404 string")
          emesg = res.body[0,256]
        else
          #print_status("Using custom 404 string of '#{emesg}'")
        end
      else
        ecode = tcode
        #print_status("Using code '#{ecode}' as not found.")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      conn = false
    rescue ::Timeout::Error, ::Errno::EPIPE
    end

    return if not conn

    dm = datastore['NoDetailMessages']

    begin
      turl = tpath+'.git/config'#'.svn/entries'

      res = send_request_cgi({
        'uri'          => turl,
        'method'       => 'GET',
        'version' => '1.0',
      }, 10)

      if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
        if dm == false
          print_status("[#{target_host}] NOT Found. #{tpath} #{res.code}")
        end
      else
        if (res.body.include?(word1) or res.body.include?(word2) or res.body.include?(word3))
          print_good("[#{target_host}:#{rport}] Git Config file found.")
        end
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end