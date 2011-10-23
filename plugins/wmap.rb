#
# Web assessment for the metasploit framework
# Efrain Torres    - et[ ] metasploit.com  2011
#
# $Id$
# $Revision$
#

require 'rabal/tree'

module Msf

class Plugin::Wmap < Msf::Plugin
	class WmapCommandDispatcher

		attr_accessor :targets

		include Msf::Ui::Console::CommandDispatcher

		def name
			"Wmap"
		end

		#
		# The initial command set
		#
		def commands
			{
				"wmap_targets"  => "Manage targets",
				"wmap_sites"   => "Manage sites",
				"wmap_run"   => "Test targets"
			}
		end

		def cmd_wmap_targets(*args)
			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-c'
					self.targets = {}
				when '-l'
					view_targets
					return
				when '-t'
					process_urls(args.shift)
				when '-h'
					print_status("Usage: wmap_targets [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-t [urls]	Define target sites (vhost1,url[space]vhost2,url) ")
					print_line("\t-c 		Clean target sites list")
					print_line("\t-l  		List all target sites")

					print_line("")
					return
				else
					print_error("Unknown flag.")
					return
				end
			end
		end

		def cmd_wmap_sites(*args)
			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-a'
					s = add_web_site(args.shift)
					if s
						print_status("Site created.")
					else
						print_error("Unable to create site")
					end
				when '-l'
					view_sites
					return
				when '-s'
					u = args.shift
					l = args.shift
					s = args.shift

					if l == nil or l.empty?
						l = 200
						s = true
					else
						l = l.to_i
						s = false
					end

					view_site_tree(u,l,s)
					return
				when '-h'
					print_status("Usage: wmap_sites [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-a [url]	Add site (vhost,url)")
					print_line("\t-l  		List all available sites")
					print_line("\t-s [urls] (level) Display site structure (vhost,url)")

					print_line("")
					return
				else
					print_error("Unknown flag.")
					return
				end
			end
		end

		def cmd_wmap_run(*args)
			# Run exploit check
			wmap_check = true
			# Run exploit if vulnerable
			wmap_runexpl = false
			# Exit wmap if session is created
			wmap_exitifsess = true

			# Formating
			sizeline = 60

			wmap_show = 2**0
			wmap_expl = 2**1

			# Exclude files can be modified by setting datastore['WMAP_EXCLUDE']
			wmap_exclude_files = '.*\.(gif|jpg|png*)$'

			run_wmap_ssl = true
			run_wmap_server = true
			run_wmap_dir_file = true
			run_wmap_query = true
			run_wmap_unique_query = true
			run_wmap_generic = true

			# If module supports datastore['VERBOSE']
			moduleverbose = false

			showprogress = false

			if not run_wmap_ssl
				print_status("Loading of wmap ssl modules disabled.")
			end
			if not run_wmap_server
				print_status("Loading of wmap server modules disabled.")
			end
			if not run_wmap_dir_file
				print_status("Loading of wmap dir and file modules disabled.")
			end
			if not run_wmap_query
				print_status("Loading of wmap query modules disabled.")
			end
			if not run_wmap_unique_query
				print_status("Loading of wmap unique query modules disabled.")
			end
			if not run_wmap_generic
				print_status("Loading of wmap generic modules disabled.")
			end

			stamp = Time.now.to_f
			mode  = 0

			eprofile = []
			using_p = false
			using_m = false
			mname = ''

			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-t'
					mode |= wmap_show
				when '-e'
					mode |= wmap_expl

					profile = args.shift

					if profile
						print_status("Using profile #{profile}.")

						begin
							File.open(profile).each do |str|
								if not str.include? '#'
									# Not a comment
									modname = str.strip
									if not modname.empty?
										eprofile << modname
									end
								end
								using_p = true
							end
						rescue
							print_error("Profile not found or invalid.")
							return
						end
					else
						print_status("Using ALL wmap enabled modules.")
					end
				when '-m'
					mode |= wmap_expl

					mname = args.shift

					if mname
						print_status("Using module #{mname}.")
					end
					using_m = true

				when '-h'
					print_status("Usage: wmap_run [options]")
					print_line("\t-h			Display this help text")
					print_line("\t-t			Show all enabled modules")
					print_line("\t-m [regex]	Launch only modules that name match provided regex.")
					print_line("\t-e [/path/to/profile]		Launch profile modules against all matched targets.")
					print_line("\t		        			No file runs all enabled modules.")
					print_line("")
					return
				end
			end

			if self.targets == nil
				print_error("Targets have not been selected.")
				return
			end

			if self.targets.keys.length == 0
				print_error("Targets have not been selected.")
				return
			end

			self.targets.each_with_index do |t, idx|
				selected_host = t[1][:host]
				selected_port = t[1][:port]
				selected_ssl  = t[1][:ssl]
				selected_vhost = t[1][:vhost]

				print_status ("Testing target:")
				print_status ("\tSite: #{selected_vhost} (#{selected_host})")
				print_status ("\tPort: #{selected_port} SSL: #{selected_ssl}")
				print_status '='* sizeline
				print_status("Testing started. #{(Time.now )}")


				if not selected_ssl
					run_wmap_ssl = false
					#print_status ("Target is not SSL. SSL modules disabled.")
				end

				# WMAP_DIR, WMAP_FILE
				matches = {}

				# WMAP_SERVER
				matches1 = {}

				# WMAP_QUERY
				matches2 = {}

				# WMAP_SSL
				matches3 = {}

				# WMAP_UNIQUE_QUERY
				matches5 = {}

				# WMAP_GENERIC
				matches10 = {}

				# EXPLOIT OPTIONS
				opt_str = nil
				bg      = false
				jobify  = false

				[ [ framework.auxiliary, 'auxiliary' ], [framework.exploits, 'exploit' ] ].each do |mtype|
					# Scan all exploit modules for matching references
					mtype[0].each_module do |n,m|
						e = m.new

						# Only include wmap_enabled plugins
						if e.respond_to?("wmap_enabled")

							penabled = e.wmap_enabled

							if penabled
								#if ( not using_p or eprofile.include? n.split('/').last ) or (using_m and n.match(mname))
								if ( using_p and eprofile.include? n.split('/').last ) or (using_m and n.to_s.match(mname)) or (not using_m and not using_p)
									#
									# First run the WMAP_SERVER plugins
									#
									case e.wmap_type
									when :WMAP_SERVER
										if run_wmap_server
											matches1[[selected_host,selected_port,selected_ssl,selected_vhost,mtype[1]+'/'+n]]=true
										end
									when :WMAP_QUERY
										if run_wmap_query
											matches2[[selected_host,selected_port,selected_ssl,selected_vhost,mtype[1]+'/'+n]]=true
										end
									when :WMAP_UNIQUE_QUERY
										if run_wmap_unique_query
											matches5[[selected_host,selected_port,selected_ssl,selected_vhost,mtype[1]+'/'+n]]=true
										end
									when :WMAP_GENERIC
										if run_wmap_generic
											matches10[[selected_host,selected_port,selected_ssl,selected_vhost,mtype[1]+'/'+n]]=true
										end
									when :WMAP_DIR, :WMAP_FILE
										if run_wmap_dir_file
											matches[[selected_host,selected_port,selected_ssl,selected_vhost,mtype[1]+'/'+n]]=true
										end
									when :WMAP_SSL
										if run_wmap_ssl
											matches3[[selected_host,selected_port,selected_ssl,selected_vhost,mtype[1]+'/'+n]]=true
										end
									else
										# Black Hole
									end
								end
							end
						end
					end
				end

				#
				# Handle modules that need to be run before all tests IF SERVER is SSL, once usually again the SSL web server.
				# :WMAP_SSL
				#

				print_status "\n=[ SSL testing ]="
				print_status "=" * sizeline

				if not selected_ssl
					print_status ("Target is not SSL. SSL modules disabled.")
				end

				idx = 0
				matches3.each_key do |xref|
					idx += 1

					begin
						mod = nil

						#Carefull with the references on this one
						if ((mod = framework.modules.create(xref[4])) == nil)
							print_status("Failed to initialize #{xref[4]}")
							next
						end

						if (mode & wmap_show != 0)
							print_status("Loaded #{xref[4]} ...")
						end

						#
						# The code is just a proof-of-concept and will be expanded in the future
						#
						if (mode & wmap_expl != 0)

							#
							# For modules to have access to the global datastore
							# i.e. set -g DOMAIN test.com
							#
							self.framework.datastore.each do |gkey,gval|
								mod.datastore[gkey]=gval
							end

							#
							# For exploits
							#
							payload = mod.datastore['PAYLOAD']
							encoder = mod.datastore['ENCODER']
							target  = mod.datastore['TARGET']
							nop     = mod.datastore['NOP']

							#
							# Parameters passed in hash xref
							#
							mod.datastore['RHOST'] = xref[0]
							mod.datastore['RHOSTS'] = xref[0]
							mod.datastore['RPORT'] = xref[1].to_s
							mod.datastore['SSL'] = xref[2]
							mod.datastore['VHOST'] = xref[3].to_s
							mod.datastore['VERBOSE'] = moduleverbose
							mod.datastore['ShowProgress'] = showprogress

							#
							# Run the plugins that only need to be
							# launched once.
							#

							wtype = mod.wmap_type

							if wtype == :WMAP_SSL
								print_status "Module #{xref[4]}"

								# To run check function for modules that are exploits
								if mod.respond_to?("check") and wmap_check
									begin
										session = mod.check_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)

										if session
											stat = '[*]'

											if (session == Msf::Exploit::CheckCode::Vulnerable)
												stat = '[+]'
											end

											print_line(stat + ' ' + session[1])

											#
											# Exploit if wmap_runexpl
											#

											if (session == Msf::Exploit::CheckCode::Vulnerable) and wmap_runexpl
												print_status("Exploiting...")

												begin
													session = mod.exploit_simple(
														'Encoder'        => encoder,
														'Payload'        => payload,
														'Target'         => target,
														'Nop'            => nop,
														'OptionStr'      => opt_str,
														'LocalInput'     => driver.input,
														'LocalOutput'    => driver.output,
														'RunAsJob'       => jobify)
												rescue ::Interrupt
													raise $!
												rescue ::Exception => e
													print_error("Exploit failed: #{e.class} #{e}")
													if(e.class.to_s != 'Msf::OptionValidateError')
														print_error("Call stack:")
														e.backtrace.each do |line|
															break if line =~ /lib.msf.base.simple/
															print_error("  #{line}")
														end
													end
												end

												# If we were given a session, let's see what we can do with it
												if (session)

													# If we aren't told to run in the background and the session can be
													# interacted with, start interacting with it by issuing the session
													# interaction command.
													if (bg == false and session.interactive?)
														print_line

														driver.run_single("sessions -q -i #{session.sid}")
														# Otherwise, log that we created a session
													else
														print_status("Session #{session.sid} created in the background.")
													end
													# If we ran the exploit as a job, indicate such so the user doesn't
													# wonder what's up.

													if wmap_exitifsess
														return
													end
												elsif (jobify)
													print_status("Exploit running as background job.")
													# Worst case, the exploit ran but we got no session, bummer.
												else
													print_status("Exploit completed, but no session was created.")
												end

											end

										else
											print_error("Check failed: The state could not be determined.")
										end

									rescue ::Exception
										print_status(" >> Exception during check launch from #{xref[4]}: #{$!}")
									end

								else
									begin
										session = mod.run_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)
									rescue ::Exception
										print_status(" >> Exception during launch from #{xref[4]}: #{$!}")
									end
								end
							end
						end

					rescue ::Exception
						print_status(" >> Exception from #{xref[4]}: #{$!}")
					end
				end


				#
				# Handle modules that need to be run before all tests, once usually again the web server.
				# :WMAP_SERVER
				#
				print_status "\n=[ Web Server testing ]="
				print_status "=" * sizeline

				idx = 0
				matches1.each_key do |xref|
					idx += 1

					begin
						mod = nil

						#Carefull with the references on this one
						if ((mod = framework.modules.create(xref[4])) == nil)
							print_status("Failed to initialize #{xref[4]}")
							next
						end

						if (mode & wmap_show != 0)
							print_status("Loaded #{xref[4]} ...")
						end

						#
						# The code is just a proof-of-concept and will be expanded in the future
						#
						if (mode & wmap_expl != 0)

							#
							# For modules to have access to the global datastore
							# i.e. set -g DOMAIN test.com
							#
							self.framework.datastore.each do |gkey,gval|
								mod.datastore[gkey]=gval
							end

							#
							# For exploits
							#
							payload = mod.datastore['PAYLOAD']
							encoder = mod.datastore['ENCODER']
							target  = mod.datastore['TARGET']
							nop     = mod.datastore['NOP']

							#
							# Parameters passed in hash xref
							#
							mod.datastore['RHOST'] = xref[0]
							mod.datastore['RHOSTS'] = xref[0]
							mod.datastore['RPORT'] = xref[1].to_s
							mod.datastore['SSL'] = xref[2]
							mod.datastore['VHOST'] = xref[3].to_s
							mod.datastore['VERBOSE'] = moduleverbose
							mod.datastore['ShowProgress'] = showprogress

							#
							# Run the plugins that only need to be
							# launched once.
							#

							wtype = mod.wmap_type

							if wtype == :WMAP_SERVER
								print_status "Module #{xref[4]}"

								# To run check function for modules that are exploits
								if mod.respond_to?("check") and wmap_check
									begin
										session = mod.check_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)

										if session
											stat = '[*]'

											if (session == Msf::Exploit::CheckCode::Vulnerable)
												stat = '[+]'
											end

											print_line(stat + ' ' + session[1])

											#
											# Exploit if wmap_runexpl
											#

											if (session == Msf::Exploit::CheckCode::Vulnerable) and wmap_runexpl
												print_status("Exploiting...")

												begin
													session = mod.exploit_simple(
														'Encoder'        => encoder,
														'Payload'        => payload,
														'Target'         => target,
														'Nop'            => nop,
														'OptionStr'      => opt_str,
														'LocalInput'     => driver.input,
														'LocalOutput'    => driver.output,
														'RunAsJob'       => jobify)
												rescue ::Interrupt
													raise $!
												rescue ::Exception => e
													print_error("Exploit failed: #{e.class} #{e}")
													if(e.class.to_s != 'Msf::OptionValidateError')
														print_error("Call stack:")
														e.backtrace.each do |line|
															break if line =~ /lib.msf.base.simple/
															print_error("  #{line}")
														end
													end
												end

												# If we were given a session, let's see what we can do with it
												if (session)

													# If we aren't told to run in the background and the session can be
													# interacted with, start interacting with it by issuing the session
													# interaction command.
													if (bg == false and session.interactive?)
														print_line

														driver.run_single("sessions -q -i #{session.sid}")
														# Otherwise, log that we created a session
													else
														print_status("Session #{session.sid} created in the background.")
													end
													# If we ran the exploit as a job, indicate such so the user doesn't
													# wonder what's up.

													if wmap_exitifsess
														return
													end
												elsif (jobify)
													print_status("Exploit running as background job.")
													# Worst case, the exploit ran but we got no session, bummer.
												else
													print_status("Exploit completed, but no session was created.")
												end

											end

										else
											print_error("Check failed: The state could not be determined.")
										end

									rescue ::Exception
										print_status(" >> Exception during check launch from #{xref[4]}: #{$!}")
									end

								else
									begin
										session = mod.run_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)
									rescue ::Exception
										print_status(" >> Exception during launch from #{xref[4]}: #{$!}")
									end
								end
							end
						end

					rescue ::Exception
						print_status(" >> Exception from #{xref[4]}: #{$!}")
					end
				end

				#
				# Handle modules to be run at every path/file
				# WMAP_DIR, WMAP_FILE
				#
				print_status "\n=[ File/Dir testing ]="
				print_status "=" * sizeline

				idx = 0
				matches.each_key do |xref|
					idx += 1

					begin
						mod = nil

						#Carefull with the references on this one
						if ((mod = framework.modules.create(xref[4])) == nil)
							print_status("Failed to initialize #{xref[4]}")
							next
						end

						if (mode & wmap_show != 0)
							print_status("Loaded #{xref[4]} ...")
						end

						#
						# The code is just a proof-of-concept and will be expanded in the future
						#
						if (mode & wmap_expl != 0)
							#
							# For modules to have access to the global datastore
							# i.e. set -g DOMAIN test.com
							#
							self.framework.datastore.each do |gkey,gval|
								mod.datastore[gkey]=gval
							end

							#
							# Parameters passed in hash xref
							#
							mod.datastore['RHOST'] = xref[0]
							mod.datastore['RHOSTS'] = xref[0]
							mod.datastore['RPORT'] = xref[1].to_s
							mod.datastore['SSL']   = xref[2]
							mod.datastore['VHOST']   = xref[3]
							mod.datastore['VERBOSE'] = moduleverbose
							mod.datastore['ShowProgress'] = showprogress

							#
							# Run the plugins that only need to be
							# launched once.
							#

							wtype = mod.wmap_type

							h = self.framework.db.workspace.hosts.find_by_address(selected_host)
							s = h.services.find_by_port(selected_port)
							w = s.web_sites.find_by_vhost(selected_vhost)

							print_status "Module #{xref[4]}:"

							test_tree = load_tree(w)
							test_tree.each do |node|

								p = node.current_path
								testpath = Pathname.new(p)
								strpath = testpath.cleanpath(false).to_s

								#
								# Fixing paths
								#

								if node.is_leaf? and not node.is_root?
									#
									# Later we can add here more checks to see if its a file
									#
								else
									if node.is_root?
										strpath = "/"
									else
										strpath = strpath.chomp + "/"
									end
								end

								strpath = strpath.gsub("//", "/")
								#print_status("Testing path: #{strpath}")

								#
								# Launch plugin depending module type.
								# Module type depends on main input type.
								# Code may be the same but it depend on final
								# versions of plugins
								#

								case wtype
								when :WMAP_FILE
									if node.is_leaf? and not node.is_root?
										#
										# Check if an exclusion regex has been defined
										#
										if self.framework.datastore['WMAP_EXCLUDE']
											excludefilestr = self.framework.datastore['WMAP_EXCLUDE']
										else
											excludefilestr = wmap_exclude_files
										end

										if not strpath.match(excludefilestr)
											mod.datastore['PATH'] = strpath
											print_status("Path: #{strpath}")

											# To run check function for modules that are exploits
											if mod.respond_to?("check") and wmap_check
												begin
													session = mod.check_simple(
														'LocalInput' 	=> driver.input,
														'LocalOutput'	=> driver.output,
														'RunAsJob'   	=> false)
												rescue ::Exception
													print_status(" >> Exception during check launch from #{xref[4]}: #{$!}")
												end
											else

												begin
													session = mod.run_simple(
														'LocalInput' 	=> driver.input,
														'LocalOutput'	=> driver.output,
														'RunAsJob'   	=> false)
												rescue ::Exception
													print_status(" >> Exception during launch from #{xref[4]}: #{$!}")
												end
											end
										end
									end
								when :WMAP_DIR
									if not node.is_leaf? or node.is_root?
										mod.datastore['PATH'] = strpath
										print_status("Path: #{strpath}")

										# To run check function for modules that are exploits
										if mod.respond_to?("check") and wmap_check
											begin
												session = mod.check_simple(
													'LocalInput' 	=> driver.input,
													'LocalOutput'	=> driver.output,
													'RunAsJob'   	=> false)
											rescue ::Exception
												print_status(" >> Exception during check launch from #{xref[4]}: #{$!}")
											end
										else

											begin
												session = mod.run_simple(
													'LocalInput' 	=> driver.input,
													'LocalOutput'	=> driver.output,
													'RunAsJob'   	=> false)
											rescue ::Exception
												print_status(" >> Exception during launch from #{xref[4]}: #{$!}")
											end
										end
									end
								end
							end
						end
					rescue ::Exception
						print_status(" >> Exception from #{xref[4]}: #{$!}")
					end
				end

				#
				# Run modules for each request to play with URI with UNIQUE query parameters.
				# WMAP_UNIQUE_QUERY
				#
				print_status "\n=[ Unique Query testing ]="
				print_status "=" * sizeline

				idx = 0
				matches5.each_key do |xref|
					idx += 1

					begin
						mod = nil

						#Carefull with the references on this one
						if ((mod = framework.modules.create(xref[4])) == nil)
							print_status("Failed to initialize #{xref[4]}")
							next
						end

						if (mode & wmap_show != 0)
							print_status("Loaded #{xref[4]} ...")
						end

						#
						# The code is just a proof-of-concept and will be expanded in the future
						#
						if (mode & wmap_expl != 0)
							#
							# For modules to have access to the global datastore
							# i.e. set -g DOMAIN test.com
							#
							self.framework.datastore.each do |gkey,gval|
								mod.datastore[gkey]=gval
							end

							#
							# Parameters passed in hash xref
							#
							mod.datastore['RHOST'] = xref[0]
							mod.datastore['RHOSTS'] = xref[0]
							mod.datastore['RPORT'] = xref[1].to_s
							mod.datastore['SSL'] = xref[2]
							mod.datastore['VHOST'] = xref[3]
							mod.datastore['VERBOSE'] = moduleverbose
							mod.datastore['ShowProgress'] = showprogress

							#
							# Run the plugins for each request that have a distinct
							# GET/POST  URI QUERY string.
							#

							wtype = mod.wmap_type

							utest_query = {}

							h = self.framework.db.workspace.hosts.find_by_address(selected_host)
							s = h.services.find_by_port(selected_port)
							w = s.web_sites.find_by_vhost(selected_vhost)

							w.web_forms.each do |form|
								#
								# Only test unique query strings by comparing signature to previous tested signatures 'path,p1,p2,pn'
								#

								datastr = ""
								typestr = ""

								temparr = []

								#print_status "---------"
								#print_status form.params
								#print_status "+++++++++"

								form.params.each do |p|
									pn, pv, pt = p
									temparr << Rex::Text.uri_encode(pn.to_s) + "=" + Rex::Text.uri_encode(pv.to_s)
								end

								datastr = temparr.join("&")	if (temparr and not temparr.empty?)

								if (utest_query.has_key?(mod.signature(form.path,datastr)) == false)

									mod.datastore['METHOD'] = form.method.upcase
									mod.datastore['PATH'] =  form.path
									mod.datastore['QUERY'] = form.query
									if form.method.upcase == 'GET'
										mod.datastore['QUERY'] = datastr
										mod.datastore['DATA'] = ""
									end
									mod.datastore['DATA'] = datastr if form.method.upcase == 'POST'
									mod.datastore['TYPES'] = typestr

									#
									# TODO: Add headers, etc.
									#

									if wtype == :WMAP_UNIQUE_QUERY
										print_status "Module #{xref[4]}"

										# To run check function for modules that are exploits
										if mod.respond_to?("check") and wmap_check
											begin
												session = mod.check_simple(
													'LocalInput' 	=> driver.input,
													'LocalOutput'	=> driver.output,
													'RunAsJob'   	=> false)
											rescue ::Exception
												print_status(" >> Exception during check launch from #{xref[4]}: #{$!}")
											end
										else

											begin
												session = mod.run_simple(
													'LocalInput' 	=> driver.input,
													'LocalOutput'	=> driver.output,
													'RunAsJob'   	=> false)
											rescue ::Exception
												print_status(" >> Exception during launch from #{xref[4]}: #{$!}")
											end
										end
									end

									#
									# Unique query tested, actually the value does not matter
									#
									#print_status("sig: #{mod.signature(form.path,varnarr.join(','))}")

									utest_query[mod.signature(form.path,datastr)]=1
								else
									#print_status("Already tested")
								end
							end
						end

					rescue ::Exception
						print_status(" >> Exception from #{xref[4]}: #{$!}")
					end
				end

				#
				# Run modules for each request to play with URI query parameters.
				# This approach will reduce the complexity of the Tree used before
				# and will make this shotgun implementation much simple.
				# WMAP_QUERY
				#
				print_status "\n=[ Query testing ]="
				print_status "=" * sizeline

				idx = 0
				matches2.each_key do |xref|
					idx += 1

					begin
						mod = nil

						#Carefull with the references on this one
						if ((mod = framework.modules.create(xref[4])) == nil)
							print_status("Failed to initialize #{xref[4]}")
							next
						end

						if (mode & wmap_show != 0)
							print_status("Loaded #{xref[4]} ...")
						end

						#
						# The code is just a proof-of-concept and will be expanded in the future
						#
						if (mode & wmap_expl != 0)

							#
							# For modules to have access to the global datastore
							# i.e. set -g DOMAIN test.com
							#
							self.framework.datastore.each do |gkey,gval|
								mod.datastore[gkey]=gval
							end

							#
							# Parameters passed in hash xref
							#
							mod.datastore['RHOST'] = xref[0]
							mod.datastore['RHOSTS'] = xref[0]
							mod.datastore['RPORT'] = xref[1].to_s
							mod.datastore['SSL'] = xref[2]
							mod.datastore['VHOST'] = xref[3].to_s
							mod.datastore['VERBOSE'] = moduleverbose
							mod.datastore['ShowProgress'] = showprogress

							#
							# Run the plugins for each request that have a distinct
							# GET/POST  URI QUERY string.
							#

							wtype = mod.wmap_type

							h = self.framework.db.workspace.hosts.find_by_address(selected_host)
							s = h.services.find_by_port(selected_port)
							w = s.web_sites.find_by_vhost(selected_vhost)

							w.web_forms.each do |req|

								datastr = ""
								typestr = ""

								temparr = []

								req.params.each do |p|
									pn, pv, pt = p
									temparr << Rex::Text.uri_encode(pn.to_s) + "=" + Rex::Text.uri_encode(pv.to_s)
								end

								datastr = temparr.join("&")	if (temparr and not temparr.empty?)

								mod.datastore['METHOD'] = req.method.upcase
								mod.datastore['PATH'] =  req.path
								if req.method.upcase == 'GET'
									mod.datastore['QUERY'] = datastr
									mod.datastore['DATA'] = ""
								end
								mod.datastore['DATA'] = datastr if req.method.upcase == 'POST'
								mod.datastore['TYPES'] = typestr


								#
								# TODO: Add method, headers, etc.
								#

								if wtype == :WMAP_QUERY
									print_status "Module #{xref[4]}"

									# To run check function for modules that are exploits
									if mod.respond_to?("check") and wmap_check
										begin
											session = mod.check_simple(
												'LocalInput' 	=> driver.input,
												'LocalOutput'	=> driver.output,
												'RunAsJob'   	=> false)
										rescue ::Exception
											print_status(" >> Exception during check launch from #{xref[4]}: #{$!}")
										end
									else

										begin
											session = mod.run_simple(
												'LocalInput' 	=> driver.input,
												'LocalOutput'	=> driver.output,
												'RunAsJob'   	=> false)
										rescue ::Exception
											print_status(" >> Exception during launch from #{xref[4]}: #{$!}")
										end
									end
								end
							end
						end

					rescue ::Exception
						print_status(" >> Exception from #{xref[4]}: #{$!}")
					end
				end

				#
				# Handle modules that need to be after all tests, once.
				# Good place to have modules that analize the test results and/or
				# launch exploits.
				# :WMAP_GENERIC
				#
				print_status "\n=[ General testing ]="
				print_status "=" * sizeline

				idx = 0
				matches10.each_key do |xref|
					idx += 1

					begin
						mod = nil

						#Carefull with the references on this one
						if ((mod = framework.modules.create(xref[4])) == nil)
							print_status("Failed to initialize #{xref[4]}")
							next
						end

						if (mode & wmap_show != 0)
							print_status("Loaded #{xref[4]} ...")
						end

						#
						# The code is just a proof-of-concept and will be expanded in the future
						#
						if (mode & wmap_expl != 0)

							#
							# For modules to have access to the global datastore
							# i.e. set -g DOMAIN test.com
							#
							self.framework.datastore.each do |gkey,gval|
								mod.datastore[gkey]=gval
							end

							#
							# Parameters passed in hash xref
							#
							mod.datastore['RHOST'] = xref[0]
							mod.datastore['RHOSTS'] = xref[0]
							mod.datastore['RPORT'] = xref[1].to_s
							mod.datastore['SSL'] = xref[2]
							mod.datatsore['VHOST'] = xref[3].to_s
							mod.datastore['VERBOSE'] = moduleverbose
							mod.datastore['ShowProgress'] = showprogress

							#
							# Run the plugins that only need to be
							# launched once.
							#

							wtype = mod.wmap_type

							if wtype == :WMAP_GENERIC
								print_status "Module #{xref[4]}"

								# To run check function for modules that are exploits
								if mod.respond_to?("check") and wmap_check
									begin
										session = mod.check_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)
									rescue ::Exception
										print_status(" >> Exception during check launch from #{xref[4]}: #{$!}")
									end
								else

									begin
										session = mod.run_simple(
											'LocalInput' 	=> driver.input,
											'LocalOutput'	=> driver.output,
											'RunAsJob'   	=> false)
									rescue ::Exception
										print_status(" >> Exception during launch from #{xref[4]}: #{$!}")
									end
								end
							end
						end

					rescue ::Exception
						print_status(" >> Exception from #{xref[4]}: #{$!}")
					end
				end

				if (mode & wmap_show != 0)
					print_status("Analysis completed in #{(Time.now.to_f - stamp)} seconds.")
					print_status("Done.")
					print_status "+" * sizeline
					print_status "\n"
				end
			end

		# EOM
		end

		def view_targets
			if self.targets == nil or self.targets.keys.length == 0
				print_status "No targets have been defined"
				return
			end

			indent = '     '

			tbl = Rex::Ui::Text::Table.new(
				'Indent'  => indent.length,
				'Header'  => 'Defined targets',
				'Columns' =>
					[
						'Id',
						'Vhost',
						'Host',
						'Port',
						'SSL',
						'Path',
					])

			self.targets.each_with_index { |t, idx|
				tbl << [ idx.to_s, t[1][:vhost], t[1][:host], t[1][:port], t[1][:ssl], t[1][:path].to_s ]
			}

			print_status tbl.to_s + "\n"
		end

		def view_sites
			indent = '     '

			tbl = Rex::Ui::Text::Table.new(
				'Indent'  => indent.length,
				'Header'  => 'Available sites',
				'Columns' =>
					[
						'Id',
						'Host',
						'Vhost',
						'Port',
						'# Pages',
						'# Forms',
					])

			idx  = 0
			self.framework.db.hosts.each do |bdhost|
				bdhost.services.each do |serv|
					serv.web_sites.each do |web|
						c = web.web_pages.count
						f = web.web_forms.count
						tbl << [ idx.to_s, bdhost.address, web.vhost, serv.port, c.to_s, f.to_s ]
						idx += 1
					end
				end
			end

			print_status tbl.to_s + "\n"

		end


		# Reusing code from hdmoore
		#
		# Allow the URL to be supplied as VHOST,URL if a custom VHOST
		# should be used. This allows for things like:
		# localhost,http://192.168.0.2/admin/

		def add_web_site(url)



				vhost = nil

				# Allow the URL to be supplied as VHOST,URL if a custom VHOST
				# should be used. This allows for things like:
				#   localhost,http://192.168.0.2/admin/

				if url !~ /^http/
					vhost,url = url.split(",", 2)
					if url.to_s.empty?
						url = vhost
						vhost = nil
					end
				end

				# Prefix http:// when the URL has no specified parameter
				if url !~ /^[a-z0-9A-Z]+:\/\//
					url = "http://" + url
				end

				uri = URI.parse(url) rescue nil
				if not uri
					print_error("Could not understand URL: #{url}")
					return
				end

				if uri.scheme !~ /^https?/
					print_error("Only http and https URLs are accepted: #{url}")
					return
				end

				ssl = false
				if uri.scheme == 'https'
					ssl = true
				end

				site = self.framework.db.report_web_site(:wait => true, :host => uri.host, :port => uri.port, :vhost => vhost, :ssl => ssl)

				return site
		end

		# Code by hdm. Modified two lines by et
		#
		def process_urls(urlstr)

			target_whitelist = []
			urls = urlstr.to_s.split(/\s+/)

			urls.each do |url|
				next if url.to_s.strip.empty?
				vhost = nil

				# Allow the URL to be supplied as VHOST,URL if a custom VHOST
				# should be used. This allows for things like:
				#   localhost,http://192.168.0.2/admin/

				if url !~ /^http/
					vhost,url = url.split(",", 2)
					if url.to_s.empty?
						url = vhost
						vhost = nil
					end
				end

				# Prefix http:// when the URL has no specified parameter
				if url !~ /^[a-z0-9A-Z]+:\/\//
					url = "http://" + url
				end

				uri = URI.parse(url) rescue nil
				if not uri
					print_error("Could not understand URL: #{url}")
					next
				end

				if uri.scheme !~ /^https?/
					print_error("Only http and https URLs are accepted: #{url}")
					next
				end

				target_whitelist << [vhost || uri.host, uri]
			end

			# Skip the DB entirely if no matches
			return if target_whitelist.length == 0

			self.targets = {}

			target_whitelist.each do |ent|
				vhost,target = ent

				host = self.framework.db.workspace.hosts.find_by_address(target.host)
				if not host
					print_error("No matching host for #{target.host}")
					next
				end
				serv = host.services.find_by_port_and_proto(target.port, 'tcp')
				if not serv
					print_error("No matching service for #{target.host}:#{target.port}")
					next
				end

				#print_status "aaa"
				#print_status framework.db.workspace.name

				#sites = serv.web_sites.find(:all, :conditions => ['vhost = ? or vhost = ?', vhost, host.address])

				sites = serv.web_sites.find(:all)

				sites.each do |site|

					#site.web_forms.find_all_by_path(target.path).each do |form|
						ckey = [ site.vhost, host.address, serv.port, target.path].join("|")
						if not self.targets[ckey]
							self.targets[ckey] = WebTarget.new
							self.targets[ckey].merge!({
								:vhost => site.vhost,
								:host  => host.address,
								:port  => serv.port,
								:ssl   => (serv.name == "https"),
								:path  => target.path
							})
							#self.targets[ckey][target.path] = []
						end

						# Store the form object in the hash for this path
						#self.targets[ckey][target.path] << target.path
					#end
				end
			end
		end

		def view_site_tree(urlstr, md, ld)

			site_whitelist = []
			urls = urlstr.to_s.split(/\s+/)

			urls.each do |url|
				next if url.to_s.strip.empty?
				vhost = nil

				# Allow the URL to be supplied as VHOST,URL if a custom VHOST
				# should be used. This allows for things like:
				#   localhost,http://192.168.0.2/admin/

				if url !~ /^http/
					vhost,url = url.split(",", 2)

					if url.to_s.empty?
						url = vhost
						vhost = nil
					end
				end

				# Prefix http:// when the URL has no specified parameter
				if url !~ /^[a-z0-9A-Z]+:\/\//
					url = "http://" + url
				end

				uri = URI.parse(url) rescue nil
				if not uri
					print_error("Could not understand URL: #{url}")
					next
				end

				if uri.scheme !~ /^https?/
					print_error("Only http and https URLs are accepted: #{url}")
					next
				end

				site_whitelist << [vhost || uri.host, uri]
			end

			# Skip the DB entirely if no matches
			return if site_whitelist.length == 0

			vsites = {}

			site_whitelist.each do |ent|
				vhost,target = ent

				host = self.framework.db.workspace.hosts.find_by_address(target.host)
				if not host
					print_error("No matching host for #{target.host}")
					next
				end
				serv = host.services.find_by_port_and_proto(target.port, 'tcp')
				if not serv
					print_error("No matching service for #{target.host}:#{target.port}")
					next
				end

				#print_status "aaa"
				#print_status framework.db.workspace.name

				sites = serv.web_sites.find(:all, :conditions => ['vhost = ? or vhost = ?', vhost, host.address])

				#sites = serv.web_sites.find(:all)

				sites.each do |site|
					#site.vhost
					#site.web_forms.find_all_by_path(target.path).each do |form|
					t = load_tree(site)
					print_tree(t,md,ld)
					print_line("\n")
				end
			end
		end

		#
		# Load website structure into a tree
		#

		def load_tree(s)

			pathchr = '/'

			wtree = Tree.new(s.vhost)

			# Load site pages
			s.web_pages.find(:all, :order => 'path').each do |req|
				tarray = req.path.to_s.split(pathchr)
				tarray.delete("")
				tpath = Pathname.new(pathchr)
				tarray.each do |df|
					wtree.add_at_path(tpath.to_s,df)
					tpath = tpath + Pathname.new(df.to_s)
				end
			end

			# Load site forms
			s.web_forms.each do |req|
				tarray = req.path.to_s.split(pathchr)
				tarray.delete("")
				tpath = Pathname.new(pathchr)
				tarray.each do |df|
					wtree.add_at_path(tpath.to_s,df)
					tpath = tpath + Pathname.new(df.to_s)
				end
			end

			return wtree
		end

		#
		# Print Tree structure. Still ugly
		#

		def print_tree(tree, maxlevel, limitlevel)
			initab = " " * 4
			indent = 6
			if  tree != nil and tree.depth <= maxlevel
				print initab + (" " * indent * tree.depth)
				if tree.depth > 0
					print "|"+("-" * (indent-1))+"/"
				end
				if tree.depth >= 0
					if tree.depth == 0
						print "[#{tree.name}]\n"+initab+(" " * indent)+"|\n"

					else
						c = tree.children.count
						if c > 0
							print tree.name	+ " (" + c.to_s+")\n"
						else
							print tree.name	+ "\n"
						end
					end
				end

				tree.children.each_pair do |name,child|
					print_tree(child,maxlevel,limitlevel)
				end
			end
		end


		#def print_tree(tree)
		#	if tree.is_leaf? and tree.depth > 0
		#		print_line(("|\t"*(tree.depth-1))+"+------"+tree.name)
		#	else
		#		print_line(("|\t"*tree.depth)+tree.name)
		#	end
		#	tree.children.each_pair do |name,child|
		#			print_tree(child)
		#	end
		#end

	end

	class WebTarget < ::Hash
		def to_url
			proto = self[:ssl] ? "https" : "http"
			"#{proto}://#{self[:host]}:#{self[:port]}#{self[:path]}"
		end
	end

	def initialize(framework, opts)
		super

		wmapversion = '1.0'
		wmapbanner = "[WMAP #{wmapversion}] ===  et [  ] metasploit.com 2011"

		add_console_dispatcher(WmapCommandDispatcher)
		print_status("#{wmapbanner}")
	end

	def cleanup
		remove_console_dispatcher('Wmap')
	end

	def name
		"wmap"
	end

	def desc
		"Web assessment plugin"
	end

protected
end

end
