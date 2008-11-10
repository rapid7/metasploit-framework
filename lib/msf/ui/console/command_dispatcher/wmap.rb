module Msf
module Ui
module Console
module CommandDispatcher
module Wmap 

		require 'rabal/tree'
		require 'rexml/document'
		require 'tempfile'
		
		# Load ActiveRecord
		require 'rubygems'
		require 'active_record'

		# 
		# MSF WMAP Web scanner		ET LowNOISE
		# et[cron]cyberspace.org   
		# 		
		
		#
		# Constants
		#

		WMAP_PATH = '/'
		WMAP_SHOW = 2**0
		WMAP_EXPL = 2**1
			
		#
		# The dispatcher's name.
		#
		def name
			"Wmap Database Backend"
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
				"wmap_website"  => "List website structure",
				"wmap_targets"  => "List all targets in the database",
				"wmap_reports" => "List all reported results",
				"wmap_run"  => "Automatically test/exploit everything",
			}
		end

		def cmd_wmap_website(*args)
			print_status("Website structure")
			if selected_host == nil
				print_error("Target not selected.")
			else	
				print_status("#{selected_host}:#{selected_port} SSL:#{selected_ssl}")
				print_tree(load_tree)
			end	
			print_status("Done.")
		end

		def cmd_wmap_targets(*args)
			args.push("-h") if args.length == 0
			
			while (arg = args.shift)
				case arg
				when '-p'
					print_status("   Id. Host\t\t\t\t\tPort\tSSL")
					
					framework.db.each_target do |tgt|
						if tgt.ssl == 1
							usessl = "[*]"
						else
							usessl = ""
						end

						maxcols = 35
						cols = maxcols - tgt.host.length
	
						thost = "#{tgt.host.to_s[0..maxcols]}"+(" "*cols)
							
						if tgt.selected == 1	
							print_status("=> #{tgt.id}. #{thost}\t#{tgt.port}\t#{usessl}")
						else
							print_status("   #{tgt.id}. #{thost}\t#{tgt.port}\t#{usessl}")
						end		
					end
					print_status("Done.")
				when '-r'
					# Default behavior to handle hosts names in the db as RHOSTS only 
					# accepts IP addresses
					resolv_hosts = false 

					framework.db.delete_all_targets
					framework.db.each_distinct_target do |req|
						if Rex::Socket.dotted_ip?(req.host)
							framework.db.create_target(req.host, req.port, req.ssl, 0)
							print_status("Added. #{req.host} #{req.port} #{req.ssl}")
						else
							print_error("RHOSTS only accepts IP addresses: #{req.host}") 
							
							if resolv_hosts
								hip = Rex::Socket.resolv_to_dotted(req.host)
								framework.db.create_target(hip, req.port, req.ssl, 0)
								print_status("Added host #{req.host} resolved as #{hip}.")
							end
						end  		
					end	
				when '-s'
					framework.db.each_target do |tgt|
						tgt.selected = 0
						tgt.save	
					end
					seltgt = framework.db.get_target(args.shift)
					if seltgt == nil
						print_error("Target id not found.")
					else
						seltgt.selected = 1
						seltgt.save
					end	
				when '-h'
					print_status("Usage: wmap_targets [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-p 		Print all available targets")
					print_line("\t-r 		Reload targets table")
					print_line("\t-s [id]	Select target for testing")
					
					print_line("")
					return
				end
			end
		end
		
		def cmd_wmap_reports(*args)
		
			entity = nil
		
			args.push("-h") if args.length == 0
			
			while (arg = args.shift)
				case arg
				when '-p'
					print_status("Id. Created\t\t\t\tTarget (host,port,ssl)")
					
					framework.db.each_report do |rep|
						print_line("#{rep.id}.  #{rep.created}\t#{rep.value}")
					end
					print_status("Done.")						
				when '-s'
					get_report_id(args.shift)
					print_status("Done.")				
				when '-h'
					print_status("Usage: wmap_reports [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-p 		Print all available reports")
					print_line("\t-s [id]	Select report for display")
					
					print_line("")
					return
				end
			end

		end
		
		#
		# A copy of the shotgun approach to website exploitation
		#
		def cmd_wmap_run(*args)

			stamp = Time.now.to_f
			mode  = 0
			
			args.push("-h") if args.length == 0
			
			while (arg = args.shift)
				case arg
				when '-t'
					mode |= WMAP_SHOW
				when '-e'
					mode |= WMAP_EXPL
					
					# Create report entry
					framework.db.create_report(0,'WMAP','REPORT',"#{selected_host},#{selected_port},#{selected_ssl}","Metasploit WMAP Report",'WMAP Scanner')
				when '-h'
					print_status("Usage: wmap_run [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-t 		Show all matching exploit modules")
					print_line("\t-e 		Launch exploits against all matched targets")
					
					print_line("")
					return
				end
			end
			
			if selected_host == nil 
				print_error("Target not selected.")
				return	
			end

			# WMAP_DIR, WMAP_FILE
			matches = {}
			
			# WMAP_SERVER
			matches1 = {}
			
			# WMAP_QUERY
			matches2 = {}
			
			# WMAP_BODY
			matches3 = {}
			
			# WMAP_HEADERS
			matches4 = {}
			
			# WMAP_UNIQUE_QUERY
			matches5 = {}
			
			# WMAP_GENERIC
			matches10 = {}
			
			
			[ [ framework.auxiliary, 'auxiliary' ] ].each do |mtype|

				# Scan all exploit modules for matching references
				mtype[0].each_module do |n,m|
					e = m.new

					# Only include wmap_enabled plugins
					if e.respond_to?("wmap_enabled") 
						
						penabled = e.wmap_enabled
						
						if (penabled)
							#
							# First run the WMAP_SERVER plugins
							#
							case e.wmap_type
							when :WMAP_SERVER
								matches1[[selected_host,selected_port,selected_ssl,mtype[1]+'/'+n]]=true
							when :WMAP_QUERY	
								matches2[[selected_host,selected_port,selected_ssl,mtype[1]+'/'+n]]=true
							when :WMAP_BODY	
								matches3[[selected_host,selected_port,selected_ssl,mtype[1]+'/'+n]]=true
							when :WMAP_HEADERS	
								matches4[[selected_host,selected_port,selected_ssl,mtype[1]+'/'+n]]=true
							when :WMAP_UNIQUE_QUERY	
								matches5[[selected_host,selected_port,selected_ssl,mtype[1]+'/'+n]]=true
							when :WMAP_GENERIC	
								matches10[[selected_host,selected_port,selected_ssl,mtype[1]+'/'+n]]=true																	
							when :WMAP_DIR, :WMAP_FILE
								matches[[selected_host,selected_port,selected_ssl,mtype[1]+'/'+n]]=true
							else
								# Black Hole	
							end	
						end
					end					
				end
			end

			#
			# Handle modules that need to be run before all tests, once usually again the web server.
			# :WMAP_SERVER
			#
			idx = 0
			matches1.each_key do |xref|
				idx += 1
				
				begin
					mod = nil

					#Carefull with the references on this one
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & WMAP_SHOW != 0)
						print_status("Loaded #{xref[3]} ...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & WMAP_EXPL != 0)

						#
						# Parameters passed in hash xref
						# 
						mod.datastore['RHOSTS'] = xref[0] 
						mod.datastore['RPORT'] = xref[1].to_s
						mod.datastore['SSL'] = xref[2].to_s

						#
						# For modules to have access to the global datastore
						# i.e. set -g DOMAIN test.com
						#
						self.framework.datastore.each do |gkey,gval|
							mod.datastore[gkey]=gval
						end

						#
						# Run the plugins that only need to be
						# launched once.
						#

						wtype = mod.wmap_type

						if wtype == :WMAP_SERVER 
							print_status("Launching #{xref[3]} #{wtype} against #{xref[0]}:#{xref[1].to_s}")

							begin
								session = mod.run_simple(
										'LocalInput' 	=> driver.input,
										'LocalOutput'	=> driver.output,
										'RunAsJob'   	=> false)
							rescue ::Exception
								print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
							end
						end
					end
					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
				end
			end

			#
			# Handle modules to be run at every path/file
			# WMAP_DIR, WMAP_FILE
			#
			idx = 0
			matches.each_key do |xref|
				idx += 1
				
				begin
					mod = nil

					#Carefull with the references on this one
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & WMAP_SHOW != 0)
						print_status("Loaded #{xref[3]} ...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & WMAP_EXPL != 0)

						#
						# Parameters passed in hash xref
						# 
						mod.datastore['RHOSTS'] = xref[0] 
						mod.datastore['RPORT'] = xref[1].to_s
						mod.datastore['SSL']   = xref[2].to_s 

						#
						# For modules to have access to the global datastore
						# i.e. set -g DOMAIN test.com
						#
						self.framework.datastore.each do |gkey,gval|
							mod.datastore[gkey]=gval
						end	

						#
						# Run the plugins that only need to be
						# launched once.
						#

						wtype = mod.wmap_type
						
						#	
						#Here is where the fun begins
						#
						test_tree = load_tree()
						test_tree.each do |node|

							testpath = Pathname.new(node.current_path)
							strpath = testpath.cleanpath(false).to_s

							#
							# Fixing paths
							#	
								
							if node.is_leaf? or node.is_root?
								#		
								# Later we can add here more checks to see if its a file
								#
							else 
								strpath = strpath.chomp + "/"
							end			
								
							#print_status("Testing path: #{strpath}")

							#
							# Launch plugin depending module type.
							# Module type depends on main input type.
							# Code may be the same but it depend on final
							# versions of plugins
							#

							case wtype
							when :WMAP_FILE  
								if node.is_leaf? 
									mod.datastore['PATH'] = strpath
									print_status("Launching #{xref[3]} #{wtype} #{strpath} against #{xref[0].to_s}:#{xref[1].to_s}...")
									
									begin
										session = mod.run_simple(
												'LocalInput' 	=> driver.input,
												'LocalOutput'	=> driver.output,
												'RunAsJob'   	=> false)
									rescue ::Exception
										print_status(" >> Exception during launch from #{name}: #{$!.to_s}")
									end	
								end	 
							when :WMAP_DIR 
								if not node.is_leaf?	
									mod.datastore['PATH'] = strpath
									print_status("Launching #{xref[3]} #{wtype} #{strpath} against #{xref[0].to_s}:#{xref[1].to_s}...")
									
									begin
										session = mod.run_simple(
												'LocalInput' 	=> driver.input,
												'LocalOutput'	=> driver.output,
												'RunAsJob'   	=> false)
									rescue ::Exception
										print_status(" >> Exception during launch from #{name}: #{$!.to_s}")
									end
								end
							end							
						end
					end					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
				end
			end	
			
			#
			# Run modules for each request to play with URI with UNIQUE query parameters.
			# WMAP_UNIQUE_QUERY
			#
			idx = 0
			matches5.each_key do |xref|
				idx += 1
				
				begin
					mod = nil

					#Carefull with the references on this one
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & WMAP_SHOW != 0)
						print_status("Loaded #{xref[3]} ...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & WMAP_EXPL != 0)

						#
						# Parameters passed in hash xref
						# 
						mod.datastore['RHOSTS'] = xref[0] 
						mod.datastore['RPORT'] = xref[1].to_s
						mod.datastore['SSL'] = xref[2].to_s

						#
						# For modules to have access to the global datastore
						# i.e. set -g DOMAIN test.com
						#
						self.framework.datastore.each do |gkey,gval|
							mod.datastore[gkey]=gval
						end

						#
						# Run the plugins for each request that have a distinct 
						# GET/POST  URI QUERY string.
						#

						wtype = mod.wmap_type
						
						utest_query = {}
						
						framework.db.each_request_target_with_query do |req|
							#
							# Only test unique query strings by comparing signature to previous tested signatures 'path,p1,p2,pn' 
							#
							if (utest_query.has_key?(mod.signature(req.path,req.query)) == false)		
								#
								# Weird bug req.method doesnt work
								# collides with some method named 'method'
								# column table renamed to 'meth'.
								# 
								mod.datastore['METHOD'] = req.meth.upcase
								mod.datastore['PATH'] =  req.path
								mod.datastore['QUERY'] = req.query
								mod.datastore['HEADERS'] = req.headers
								mod.datastore['BODY'] = req.body
								#
								# TODO: Add method, headers, etc.
								# 
							
								if wtype == :WMAP_UNIQUE_QUERY 
									print_status("Launching #{xref[3]} #{wtype} against #{xref[0]}:#{xref[1].to_s}")

									begin
										session = mod.run_simple(
												'LocalInput' 	=> driver.input,
												'LocalOutput'	=> driver.output,
												'RunAsJob'   	=> false)
									rescue ::Exception
										print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
									end
								end
								
								#
								# Unique query tested, actually the value does not matter
								#
								utest_query[mod.signature(req.path,req.query)]=1 
							end
						end
					end
					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
				end
			end
			
			#
			# Run modules for each request to play with URI query parameters.
			# This approach will reduce the complexity of the Tree used before 
			# and will make this shotgun implementation much simple.
			# WMAP_QUERY
			#
			idx = 0
			matches2.each_key do |xref|
				idx += 1
				
				begin
					mod = nil

					#Carefull with the references on this one
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & WMAP_SHOW != 0)
						print_status("Loaded #{xref[3]} ...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & WMAP_EXPL != 0)

						#
						# Parameters passed in hash xref
						# 
						mod.datastore['RHOSTS'] = xref[0] 
						mod.datastore['RPORT'] = xref[1].to_s
						mod.datastore['SSL'] = xref[2].to_s

						#
						# For modules to have access to the global datastore
						# i.e. set -g DOMAIN test.com
						#
						self.framework.datastore.each do |gkey,gval|
							mod.datastore[gkey]=gval
						end

						#
						# Run the plugins for each request that have a distinct 
						# GET/POST  URI QUERY string.
						#

						wtype = mod.wmap_type
						
						
						framework.db.each_request_target_with_query do |req|
							#
							# Weird bug req.method doesnt work
							# collides with some method named 'method'
							# column table renamed to 'meth'.
							# 
							mod.datastore['METHOD'] = req.meth.upcase
							mod.datastore['PATH'] =  req.path
							mod.datastore['QUERY'] = req.query
							mod.datastore['HEADERS'] = req.headers
							mod.datastore['BODY'] = req.body
							#
							# TODO: Add method, headers, etc.
							# 
							
							if wtype == :WMAP_QUERY 
								print_status("Launching #{xref[3]} #{wtype} against #{xref[0]}:#{xref[1].to_s}")

								begin
									session = mod.run_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)
								rescue ::Exception
									print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
								end
							end
						end
					end
					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
				end
			end
			
			#
			# Run modules for each request to play with request bodies.
			# WMAP_BODY
			#
			idx = 0
			matches3.each_key do |xref|
				idx += 1
				
				begin
					mod = nil

					#Carefull with the references on this one
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & WMAP_SHOW != 0)
						print_status("Loaded #{xref[3]} ...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & WMAP_EXPL != 0)

						#
						# Parameters passed in hash xref
						# 
						mod.datastore['RHOSTS'] = xref[0] 
						mod.datastore['RPORT'] = xref[1].to_s
						mod.datastore['SSL'] = xref[2].to_s

						#
						# For modules to have access to the global datastore
						# i.e. set -g DOMAIN test.com
						#
						self.framework.datastore.each do |gkey,gval|
							mod.datastore[gkey]=gval
						end

						#
						# Run the plugins for each request for all headers  
						# This can be improved alot . Later versions
						# Should only tests on unique requests.
						#

						wtype = mod.wmap_type
						
						
						framework.db.each_request_target_with_body do |req|
							#
							# Weird bug req.method doesnt work
							# collides with some method named 'method'
							# column table renamed to 'meth'.
							# 
							mod.datastore['METHOD'] = req.meth.upcase
							mod.datastore['PATH'] =  req.path
							mod.datastore['QUERY'] = req.query
							mod.datastore['HEADERS'] = req.headers
							mod.datastore['BODY'] = req.body
							#
							# TODO: Add method, headers, etc.
							# 
							
							if wtype == :WMAP_BODY 
								print_status("Launching #{xref[3]} #{wtype} against #{xref[0]}:#{xref[1].to_s}")

								begin
									session = mod.run_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)
								rescue ::Exception
									print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
								end
							end
						end
					end
					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
				end
			end
			
			#
			# Run modules for each request to play with request headers.
			# WMAP_HEADERS
			#
			idx = 0
			matches4.each_key do |xref|
				idx += 1
				
				begin
					mod = nil

					#Carefull with the references on this one
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & WMAP_SHOW != 0)
						print_status("Loaded #{xref[3]} ...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & WMAP_EXPL != 0)

						#
						# Parameters passed in hash xref
						# 
						mod.datastore['RHOSTS'] = xref[0] 
						mod.datastore['RPORT'] = xref[1].to_s
						mod.datastore['SSL'] = xref[2].to_s

						#
						# For modules to have access to the global datastore
						# i.e. set -g DOMAIN test.com
						#
						self.framework.datastore.each do |gkey,gval|
							mod.datastore[gkey]=gval
						end

						#
						# Run the plugins for each request for all headers  
						# This can be improved alot . Later versions
						# Should only tests on unique requests.
						#

						wtype = mod.wmap_type
						
						
						framework.db.each_request_target_with_headers do |req|
							#
							# Weird bug req.method doesnt work
							# collides with some method named 'method'
							# column table renamed to 'meth'.
							# 
							mod.datastore['METHOD'] = req.meth.upcase
							mod.datastore['PATH'] =  req.path
							mod.datastore['QUERY'] = req.query
							mod.datastore['HEADERS'] = req.headers
							mod.datastore['BODY'] = req.body
							#
							# TODO: Add method, headers, etc.
							# 
							
							if wtype == :WMAP_HEADERS 
								print_status("Launching #{xref[3]} #{wtype} against #{xref[0]}:#{xref[1].to_s}")

								begin
									session = mod.run_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)
								rescue ::Exception
									print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
								end
							end
						end
					end
					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
				end
			end
			
			#
			# Handle modules that need to be after all tests, once.
			# Good place to have modules that analize the test results and/or
			# launch exploits.
			# :WMAP_GENERIC
			#
			idx = 0
			matches10.each_key do |xref|
				idx += 1
				
				begin
					mod = nil

					#Carefull with the references on this one
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & WMAP_SHOW != 0)
						print_status("Loaded #{xref[3]} ...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & WMAP_EXPL != 0)

						#
						# Parameters passed in hash xref
						# 
						mod.datastore['RHOSTS'] = xref[0] 
						mod.datastore['RPORT'] = xref[1].to_s
						mod.datastore['SSL'] = xref[2].to_s

						#
						# For modules to have access to the global datastore
						# i.e. set -g DOMAIN test.com
						#
						self.framework.datastore.each do |gkey,gval|
							mod.datastore[gkey]=gval
						end

						#
						# Run the plugins that only need to be
						# launched once.
						#

						wtype = mod.wmap_type

						if wtype == :WMAP_GENERIC 
							print_status("Launching #{xref[3]} #{wtype} against #{xref[0]}:#{xref[1].to_s}")

							begin
								session = mod.run_simple(
										'LocalInput' 	=> driver.input,
										'LocalOutput'	=> driver.output,
										'RunAsJob'   	=> false)
							rescue ::Exception
								print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
							end
						end
					end
					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
				end
			end
		
			if (mode & WMAP_SHOW != 0)
				print_status("Analysis completed in #{(Time.now.to_f - stamp).to_s} seconds.")	
				print_status("Done.")
			end
						
		# EOM
		end
	

		#
		# Load website structure into a tree
		#

		def load_tree
			wtree = Tree.new("ROOT_TREE")
			
			if selected_host == nil
				print_error("Target not selected")
			else
			
				framework.db.each_request_target do |req|	
					tarray = req.path.to_s.split(WMAP_PATH)
					tarray.delete("")
					tpath = Pathname.new(WMAP_PATH)

					tarray.each do |df|
						wtree.add_at_path(tpath.to_s,df)
						tpath = tpath + Pathname.new(df.to_s)
					end
				end
			end	
			return wtree
		end

		#
		# Print Tree structure. Ugly
		#

		def print_tree(tree)
			if tree.is_leaf?
				print_line(("|\t"*(tree.depth-1))+"+------"+tree.name)
			else
				print_line(("|\t"*tree.depth)+tree.name)
			end		
			tree.children.each_pair do |name,child|
					print_tree(child)
			end
		end
		
		#
		# This scary method iterates the reports table to display the report 
		#
		def get_report_id(id) 
			begin
				par = framework.db.report_parent(id)
			rescue ::Exception
				print_error("Report error #{$!.to_s}")
				return
			end
			
			print_line("\t#{par.entity} #{par.etype}: #{par.value} #{par.notes} [#{par.created}]")
			
			framework.db.report_children(id).each do |chl|
				get_report_id(chl.id) 
			end
		end
		
		#
		# Selected target
		#
		def selected_host
			framework.db.selected_host
		end
		
		def selected_port
			framework.db.selected_port
		end
		
		def selected_ssl
			framework.db.selected_ssl
		end
		
		
end
end
end
end
end
