##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP Subversion  Scanner',
			'Version'     => '$Revision: 6485 $',
			'Description' => 'Detect subversion directories and files and analize its content. Only SVN Version > 7 supported',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)
		
		register_options(
			[
				OptString.new('PATH', [ true,  "The test path to .svn directory", '/']),
				OptBool.new('GET_SOURCE', [ false, "Attempt to obtain file source code", true ]),
				OptBool.new('SHOW_SOURCE', [ false, "Show source code", true ])
				
			], self.class)									
	end

	def run_host(target_host)

		begin
			tpath = datastore['PATH'] 	
			if tpath[-1,1] != '/'
				tpath += '/'
			end
			
			turl = tpath+'.svn/entries'
		
			res = send_request_cgi({
				'uri'          => turl,					
				'method'       => 'GET',
				'version' => '1.0',
			}, 10)

						
			if res.code == 200 and res.body.length > 0 
				
				rep_id = wmap_base_report_id(
						wmap_target_host,
						wmap_target_port,
						wmap_target_ssl
				)
			
				vuln_id = wmap_report(rep_id,'VULNERABILITY','SVN_ENTRIES',"#{turl}","SVN Entries file found.")
			
				vers = res.body[0..1].chomp.to_i
				if vers <= 6
					print_error("Version #{vers} not supported")
					return
				end
				n = 0
				res.body.split("\f\n").each do |record|
					resarr = []
					resarr = record.to_s.split("\n")

					if n==0
						#first record
						version = resarr[0]
						sname = "CURRENT"
						skind = resarr[2]
						srevision = resarr[3]
						surl = resarr[4]
						slastauthor = resarr[11]
						
					else
						sname = resarr[0]
						skind = resarr[1]
						srevision = resarr[2]
						surl = resarr[3]
						slastauthor = resarr[10]
					end	

					print_status("#{skind} #{sname} [#{slastauthor}]")
					
					if slastauthor and slastauthor.length > 0
						wmap_report(vuln_id,'SVN_ENTRIES','USERNAME',"#{slastauthor}","Username found.")
					end
					
					if skind
						if skind == 'dir'					
							wmap_report(vuln_id,'SVN_ENTRIES','DIRECTORY',"#{sname}","Directory in .svn/entries found.")
						end
						
						if skind == 'file'
							ent_id = wmap_report(vuln_id,'SVN_ENTRIES','FILE',"#{sname}","File in .svn/entries found.")
							
							if datastore['GET_SOURCE']
								print_status("Trying to get file #{sname} source code.")
						
								begin
									turl = tpath+'.svn/text-base/'+sname+'.svn-base'
									print_status("Location: #{turl}")
		
									srcres = send_request_cgi({
										'uri'          => turl,					
										'method'       => 'GET',
										'version' => '1.0',
									}, 10)
							
									if srcres and srcres.body.length > 0
										if datastore['SHOW_SOURCE']
											print_status("#{srcres.body}")
										end
										wmap_report(ent_id,'SVN_SOURCE_CODE','CODE',"#{srcres.body}","Source code found.")
									end
								rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
								rescue ::Timeout::Error, ::Errno::EPIPE
								end
							end	
						end
					end
					n += 1
				end
				print_status("Done. #{n} records.")
			else
					print_error("#{turl} file not found.")
			end	
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

