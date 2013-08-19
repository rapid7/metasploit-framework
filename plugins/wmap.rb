#
# Web assessment for the metasploit framework
# Efrain Torres    - et[ ] metasploit.com  2012
#
# $Id$
# $Revision$
#

require 'rabal/tree'
require 'msf/core/rpc/v10/client'
#require 'fileutils'

module Msf

class Plugin::Wmap < Msf::Plugin
	class WmapCommandDispatcher

		attr_accessor :wmapmodules  # Enabled Wmap modules
		attr_accessor :targets      # Targets
		attr_accessor :lastsites    # Temp location of previously obtained sites
		attr_accessor :rpcarr       # Array or rpc connections
		attr_accessor :njobs        # Max number of jobs
		attr_accessor :nmaxdisplay  # Flag to stop displaying the same mesg
		attr_accessor :runlocal		# Flag to run local modules only
		attr_accessor :masstop		# Flag to stop everything
		attr_accessor :killwhenstop # Kill process when exiting

		include Msf::Ui::Console::CommandDispatcher

		def name
			"wmap"
		end

		#
		# The initial command set
		#
		def commands
			{
				"wmap_targets"  => "Manage targets",
				"wmap_sites"   => "Manage sites",
				"wmap_nodes" => "Manage nodes",
				"wmap_run"   => "Test targets",
				"wmap_modules"  => "Manage wmap modules",
				"wmap_vulns"  => "Display web vulns",
			}
		end

		def cmd_wmap_vulns(*args)
			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-l'
					view_vulns
					return
				when '-h'
					print_status("Usage: wmap_vulns [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-l 		Display web vulns table")

					print_line("")
					return
				else
					print_error("Unknown flag.")
					return
				end
			end
		end


		def cmd_wmap_modules(*args)
			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-l'
					view_modules
					return
				when '-r'
					load_wmap_modules(true)
					return
				when '-h'
					print_status("Usage: wmap_modules [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-l  		List all wmap enabled modules")
					print_line("\t-r		Reload wmap modules")

					print_line("")
					return
				else
					print_error("Unknown flag.")
					return
				end
			end
		end

		def cmd_wmap_targets(*args)
			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-c'
					self.targets = Hash.new()
				when '-l'
					view_targets
					return
				when '-t'
					process_urls(args.shift)
				when '-d'
					process_ids(args.shift)
				when '-h'
					print_status("Usage: wmap_targets [options]")
					print_line("\t-h 		Display this help text")
					print_line("\t-t [urls]	Define target sites (vhost1,url[space]vhost2,url) ")
					print_line("\t-d [ids]	Define target sites (id1, id2, id3 ...)")
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
				when '-d'
					del_idx = args
					if del_idx
						delete_sites(del_idx.select {|d| d =~ /^[0-9]*$/}.map(&:to_i).uniq)
						return
					else
						print_error("Provide index of site to delete")
					end
				when '-l'
					view_sites
					return
				when '-s'
					u = args.shift
					l = args.shift
					s = args.shift

					if not u
						return
					end

					if l == nil or l.empty?
						l = 200
						s = true
					else
						l = l.to_i
						s = false
					end

					if u.include? 'http'
						# Parameters are in url form
						view_site_tree(u,l,s)
					else
							# Parameters are digits
							if !self.lastsites or self.lastsites.length == 0
							view_sites
							print_status ("Web sites ids. referenced from previous table.")
						end

						target_whitelist = []
						ids = u.to_s.split(/,/)

						ids.each do |id|
							next if id.to_s.strip.empty?

							if id.to_i > self.lastsites.length
								print_error("Skipping id #{id}...")
							else
								target_whitelist << self.lastsites[id.to_i]
								#print_status("Loading #{self.lastsites[id.to_i]}.")
							end
						end

						# Skip the DB entirely if no matches
						return if target_whitelist.length == 0

						if not self.targets
							self.targets = Hash.new()
						end

						target_whitelist.each do |ent|
							view_site_tree(ent,l,s)
						end
					end
					return
				when '-h'
					print_status("Usage: wmap_sites [options]")
					print_line("\t-h        Display this help text")
					print_line("\t-a [url]  Add site (vhost,url)")
					print_line("\t-d [ids]  Delete sites (separate ids with space)")
					print_line("\t-l        List all available sites")
					print_line("\t-s [id]   Display site structure (vhost,url|ids) (level)")

					print_line("")
					return
				else
					print_error("Unknown flag.")
					return
				end
			end
		end

		def cmd_wmap_nodes(*args)

			if not self.rpcarr
				self.rpcarr=Hash.new()
			end

			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-a'
					h = args.shift
					r = args.shift
					s = args.shift
					u = args.shift
					p = args.shift

					res = rpc_add_node(h,r,s,u,p,false)
					if res
						print_status("Node created.")
					else
						print_error("Unable to create node")
					end
				when '-c'
					idref = args.shift

					if not idref
						print_error("No id defined")
						return
					end
					if idref.upcase == 'ALL'
						print_status("All nodes removed")
						self.rpcarr = Hash.new()
					else
						idx=0
						self.rpcarr.each do |k,v|
							if idx == idref.to_i
								self.rpcarr.delete(k)
								print_status("Node deleted #{k}")
							end
							idx += 1
						end
					end
				when '-d'
					host = args.shift
					port = args.shift
					user = args.shift
					pass = args.shift
					dbname = args.shift

					res = rpc_db_nodes(host,port,user,pass,dbname)
					if res
						print_status("OK.")
					else
						print_error("Error")
					end
				when '-l'
					rpc_list_nodes
					return
				when '-j'
					rpc_view_jobs
					return
				when '-k'
					node = args.shift
					jid = args.shift
					rpc_kill_node(node,jid)
					return
				when '-h'
					print_status("Usage: wmap_nodes [options]")
					print_line("\t-h                            Display this help text")
					print_line("\t-c id                         Remove id node (Use ALL for ALL nodes")
					print_line("\t-a host port ssl user pass    Add node")
					print_line("\t-d host port user pass db     Force all nodes to connect to db")
					print_line("\t-j                            View detailed jobs")
					print_line("\t-k ALL|id ALL|job_id          Kill jobs on node")
					print_line("\t-l                            List all current nodes")

					print_line("")
					return
				else
					print_error("Unknown flag.")
					return
				end
			end
		end

		def cmd_wmap_run(*args)
			# Stop everything
			self.masstop = false
			self.killwhenstop  = true

			trap("INT") {
				print_error("Stopping execution...")
				self.masstop = true
				if self.killwhenstop
					rpc_kill_node('ALL','ALL')
				end
			}

			# Max numbers of concurrent jobs per node
			self.njobs = 25
			self.nmaxdisplay = false
			self.runlocal = false

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

			if not self.rpcarr
				self.rpcarr = Hash.new()
			end

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
			usinginipath = false

			mname = ''
			inipathname = '/'

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
				when '-p'
					mode |= wmap_expl

					inipathname = args.shift

					if inipathname
						print_status("Using initial path #{inipathname}.")
					end
					usinginipath = true

				when '-h'
					print_status("Usage: wmap_run [options]")
					print_line("\t-h                        Display this help text")
					print_line("\t-t                        Show all enabled modules")
					print_line("\t-m [regex]                Launch only modules that name match provided regex.")
					print_line("\t-p [regex]                Only test path defined by regex.")
					print_line("\t-e [/path/to/profile]     Launch profile modules against all matched targets.")
					print_line("\t                          (No profile file runs all enabled modules.)")
					print_line("")
					return
				else
					print_error("Unknown flag")
					return
				end
			end

			if (self.rpcarr.length == 0) and (mode & wmap_show == 0)
				print_error("NO WMAP NODES DEFINED. Executing local modules")
				self.runlocal = true
			end

			if self.targets == nil
				print_error("Targets have not been selected.")
				return
			end

			if self.targets.keys.length == 0
				print_error("Targets have not been selected.")
				return
			end

			execmod = true
			if (mode & wmap_show != 0)
				execmod = false
			end

			self.targets.each_with_index do |t, idx|

				selected_host = t[1][:host]
				selected_port = t[1][:port]
				selected_ssl  = t[1][:ssl]
				selected_vhost = t[1][:vhost]

				print_status ("Testing target:")
				print_status ("\tSite: #{selected_vhost} (#{selected_host})")
				print_status ("\tPort: #{selected_port} SSL: #{selected_ssl}")
				print_line '='* sizeline
				print_status("Testing started. #{(Time.now )}")

				if not selected_ssl
					run_wmap_ssl = false
					#print_status ("Target is not SSL. SSL modules disabled.")
				end

				# wmap_dir, wmap_file
				matches = Hash.new()

				# wmap_server
				matches1 = Hash.new()

				# wmap_query
				matches2 = Hash.new()

				# wmap_ssl
				matches3 = Hash.new()

				# wmap_unique_query
				matches5 = Hash.new()

				# wmap_generic
				matches10 = Hash.new()

				# OPTIONS
				opt_str = nil
				jobify  = false

				# This will be clean later
				load_wmap_modules(false)

				self.wmapmodules.each do |w|
					case w[2]
					when :wmap_server
						if run_wmap_server
							matches1[w]=true
						end
					when :wmap_query
						if run_wmap_query
							matches2[w]=true
						end
					when :wmap_unique_query
						if run_wmap_unique_query
							matches5[w]=true
						end
					when :wmap_generic
						if run_wmap_generic
							matches10[w]=true
						end
					when :wmap_dir, :wmap_file
						if run_wmap_dir_file
							matches[w]=true
						end
					when :wmap_ssl
						if run_wmap_ssl
							matches3[w]=true
						end
					else
						# Black Hole
					end
				end

				# Execution order (orderid)
				matches = sort_by_orderid(matches)
				matches1 = sort_by_orderid(matches1)
				matches2 = sort_by_orderid(matches2)
				matches3 = sort_by_orderid(matches3)
				matches5 = sort_by_orderid(matches5)
				matches10 = sort_by_orderid(matches10)

				#
				# Handle modules that need to be run before all tests IF SERVER is SSL, once usually again the SSL web server.
				# :wmap_ssl
				#

				print_status "\n=[ SSL testing ]="
				print_line "=" * sizeline

				if not selected_ssl
					print_status ("Target is not SSL. SSL modules disabled.")
				end

				idx = 0
				matches3.each_key do |xref|
					if self.masstop
						print_error("STOPPED.")
						return
					end

					# Module not part of profile or not match
					if ( using_p and eprofile.include? xref[0].split('/').last ) or (using_m and xref[0].to_s.match(mname)) or (not using_m and not using_p)
						idx += 1

						begin
							# Module options hash
							modopts = Hash.new()

							#
							# The code is just a proof-of-concept and will be expanded in the future
							#
							print_status "Module #{xref[0]}"

							if (mode & wmap_expl != 0)

								#
								# For modules to have access to the global datastore
								# i.e. set -g DOMAIN test.com
								#
								self.framework.datastore.each do |gkey,gval|
									modopts[gkey]=gval
								end

								#
								# Parameters passed in hash xref
								#
								modopts['RHOST'] = selected_host
								modopts['RHOSTS'] = selected_host
								modopts['RPORT'] = selected_port.to_s
								modopts['SSL'] = selected_ssl
								modopts['VHOST'] = selected_vhost.to_s
								modopts['VERBOSE'] = moduleverbose
								modopts['ShowProgress'] = showprogress
								modopts['RunAsJob'] = jobify

								begin
									if execmod
										rpcnode = rpc_round_exec(xref[0],xref[1], modopts, self.njobs)
									end
								rescue ::Exception
									print_status(" >> Exception during launch from #{xref[0]}: #{$!}")
								end
							end

						rescue ::Exception
							print_status(" >> Exception from #{xref[0]}: #{$!}")
						end
					end
				end

				#
				# Handle modules that need to be run before all tests, once usually again the web server.
				# :wmap_server
				#
				print_status "\n=[ Web Server testing ]="
				print_line "=" * sizeline

				idx = 0
				matches1.each_key do |xref|

					if self.masstop
						print_error("STOPPED.")
						return
					end

					# Module not part of profile or not match
					if ( using_p and eprofile.include? xref[0].split('/').last ) or (using_m and xref[0].to_s.match(mname)) or (not using_m and not using_p)
						idx += 1

						begin
							# Module options hash
							modopts = Hash.new()

							#
							# The code is just a proof-of-concept and will be expanded in the future
							#

							print_status "Module #{xref[0]}"

							if (mode & wmap_expl != 0)

								#
								# For modules to have access to the global datastore
								# i.e. set -g DOMAIN test.com
								#
								self.framework.datastore.each do |gkey,gval|
									modopts[gkey]=gval
								end

								#
								# Parameters passed in hash xref
								#
								modopts['RHOST'] = selected_host
								modopts['RHOSTS'] = selected_host
								modopts['RPORT'] = selected_port.to_s
								modopts['SSL'] = selected_ssl
								modopts['VHOST'] = selected_vhost.to_s
								modopts['VERBOSE'] = moduleverbose
								modopts['ShowProgress'] = showprogress
								modopts['RunAsJob'] = jobify

								begin
									if execmod
										rpcnode = rpc_round_exec(xref[0],xref[1], modopts, self.njobs)
									end
								rescue ::Exception
									print_status(" >> Exception during launch from #{xref[0]}: #{$!}")
								end
							end

						rescue ::Exception
							print_status(" >> Exception from #{xref[0]}: #{$!}")
						end
					end
				end

				#
				# Handle modules to be run at every path/file
				# wmap_dir, wmap_file
				#
				print_status "\n=[ File/Dir testing ]="
				print_line "=" * sizeline

				idx = 0
				matches.each_key do |xref|

					if self.masstop
						print_error("STOPPED.")
						return
					end

					# Module not part of profile or not match
					if ( using_p and eprofile.include? xref[0].split('/').last ) or (using_m and xref[0].to_s.match(mname)) or (not using_m and not using_p)
						idx+=1

						begin
							# Module options hash
							modopts = Hash.new()

							#
							# The code is just a proof-of-concept and will be expanded in the future
							#

							print_status "Module #{xref[0]}"

							if (mode & wmap_expl != 0)
								#
								# For modules to have access to the global datastore
								# i.e. set -g DOMAIN test.com
								#
								self.framework.datastore.each do |gkey,gval|
									modopts[gkey]=gval
								end

								#
								# Parameters passed in hash xref
								#
								modopts['RHOST'] = selected_host
								modopts['RHOSTS'] = selected_host
								modopts['RPORT'] = selected_port.to_s
								modopts['SSL'] = selected_ssl
								modopts['VHOST'] = selected_vhost.to_s
								modopts['VERBOSE'] = moduleverbose
								modopts['ShowProgress'] = showprogress
								modopts['RunAsJob'] = jobify

								#
								# Run the plugins that only need to be
								# launched once.
								#

								wtype = xref[2]

								h = self.framework.db.workspace.hosts.find_by_address(selected_host)
								s = h.services.find_by_port(selected_port)
								w = s.web_sites.find_by_vhost(selected_vhost)

								test_tree = load_tree(w)
								test_tree.each do |node|

									if self.masstop
										print_error("STOPPED.")
										return
									end

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
									when :wmap_file
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
												if (not usinginipath) or (usinginipath and strpath.match(inipathname))
													modopts['PATH'] = strpath
													print_status("Path: #{strpath}")

													begin
														if execmod
															rpcnode = rpc_round_exec(xref[0],xref[1], modopts, self.njobs)
														end
													rescue ::Exception
														print_status(" >> Exception during launch from #{xref[0]}: #{$!}")
													end
												end
											end
										end
									when :wmap_dir
										if (node.is_leaf? and not strpath.include? ".") or node.is_root? or not node.is_leaf?
											if (not usinginipath) or (usinginipath and strpath.match(inipathname))

												modopts['PATH'] = strpath
												print_status("Path: #{strpath}")

												begin
													if execmod
														rpcnode = rpc_round_exec(xref[0],xref[1], modopts, njobs)
													end
												rescue ::Exception
													print_status(" >> Exception during launch from #{xref[0]}: #{$!}")
												end
											end
										end
									end
								end
							end
						rescue ::Exception
							print_status(" >> Exception from #{xref[0]}: #{$!}")
						end
					end
				end

				#
				# Run modules for each request to play with URI with UNIQUE query parameters.
				# wmap_unique_query
				#
				print_status "\n=[ Unique Query testing ]="
				print_line "=" * sizeline

				idx = 0
				matches5.each_key do |xref|

					if self.masstop
						print_error("STOPPED.")
						return
					end

					# Module not part of profile or not match
					if ( using_p and eprofile.include? xref[0].split('/').last ) or (using_m and xref[0].to_s.match(mname)) or (not using_m and not using_p)
						idx += 1

						begin
							# Module options hash
							modopts = Hash.new()

							#
							# The code is just a proof-of-concept and will be expanded in the future
							#

							print_status "Module #{xref[0]}"

							if (mode & wmap_expl != 0)
								#
								# For modules to have access to the global datastore
								# i.e. set -g DOMAIN test.com
								#
								self.framework.datastore.each do |gkey,gval|
									modopts[gkey]=gval
								end

								#
								# Parameters passed in hash xref
								#

								modopts['RHOST'] = selected_host
								modopts['RHOSTS'] = selected_host
								modopts['RPORT'] = selected_port.to_s
								modopts['SSL'] = selected_ssl
								modopts['VHOST'] = selected_vhost.to_s
								modopts['VERBOSE'] = moduleverbose
								modopts['ShowProgress'] = showprogress
								modopts['RunAsJob'] = jobify

								#
								# Run the plugins for each request that have a distinct
								# GET/POST  URI QUERY string.
								#

								utest_query = Hash.new()

								h = self.framework.db.workspace.hosts.find_by_address(selected_host)
								s = h.services.find_by_port(selected_port)
								w = s.web_sites.find_by_vhost(selected_vhost)

								w.web_forms.each do |form|

									if self.masstop
										print_error("STOPPED.")
										return
									end

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
										if pn
											if not pn.empty?
												if not pv or pv.empty?
													#TODO add value based on param name
													pv = "aaa"
												end

												#temparr << pn.to_s + "=" + Rex::Text.uri_encode(pv.to_s)
												temparr << pn.to_s + "=" + pv.to_s
											end
										else
											print_error("Blank parameter name. Form #{form.path}")
										end
									end

									datastr = temparr.join("&")	if (temparr and not temparr.empty?)

									if (utest_query.has_key?(signature(form.path,datastr)) == false)

										modopts['METHOD'] = form.method.upcase
										modopts['PATH'] =  form.path
										modopts['QUERY'] = form.query
										if form.method.upcase == 'GET'
											modopts['QUERY'] = datastr
											modopts['DATA'] = ""
										end
										if form.method.upcase == 'POST'
											modopts['DATA'] = datastr
										end
										modopts['TYPES'] = typestr

										#
										# TODO: Add headers, etc.
										#
										if (not usinginipath) or (usinginipath and form.path.match(inipathname))

											print_status "Path #{form.path}"
											#print_status("Unique PATH #{modopts['PATH']}")
											#print_status("Unique GET #{modopts['QUERY']}")
											#print_status("Unique POST #{modopts['DATA']}")
											#print_status("MODOPTS: #{modopts}")

											begin
												if execmod
													rpcnode = rpc_round_exec(xref[0],xref[1], modopts, self.njobs)
												end
												utest_query[signature(form.path,datastr)]=1
											rescue ::Exception
												print_status(" >> Exception during launch from #{xref[0]}: #{$!}")
											end
										end
									else
										#print_status("Already tested")
									end
								end
							end

						rescue ::Exception
							print_status(" >> Exception from #{xref[0]}: #{$!}")
						end
					end
				end

				#
				# Run modules for each request to play with URI query parameters.
				# This approach will reduce the complexity of the Tree used before
				# and will make this shotgun implementation much simple.
				# wmap_query
				#
				print_status "\n=[ Query testing ]="
				print_line "=" * sizeline

				idx = 0
				matches2.each_key do |xref|

					if self.masstop
						print_error("STOPPED.")
						return
					end

					# Module not part of profile or not match
					if not ( using_p and eprofile.include? xref[0].split('/').last ) or (using_m and xref[0].to_s.match(mname)) or (not using_m and not using_p)
						idx += 1

						begin
							# Module options hash
							modopts = Hash.new()

							#
							# The code is just a proof-of-concept and will be expanded in the future
							#

							print_status "Module #{xref[0]}"

							if (mode & wmap_expl != 0)

								#
								# For modules to have access to the global datastore
								# i.e. set -g DOMAIN test.com
								#
								self.framework.datastore.each do |gkey,gval|
									modopts[gkey]=gval
								end

								#
								# Parameters passed in hash xref
								#

								modopts['RHOST'] = selected_host
								modopts['RHOSTS'] = selected_host
								modopts['RPORT'] = selected_port.to_s
								modopts['SSL'] = selected_ssl
								modopts['VHOST'] = selected_vhost.to_s
								modopts['VERBOSE'] = moduleverbose
								modopts['ShowProgress'] = showprogress
								modopts['RunAsJob'] = jobify

								#
								# Run the plugins for each request that have a distinct
								# GET/POST  URI QUERY string.
								#

								h = self.framework.db.workspace.hosts.find_by_address(selected_host)
								s = h.services.find_by_port(selected_port)
								w = s.web_sites.find_by_vhost(selected_vhost)

								w.web_forms.each do |req|

									if self.masstop
										print_error("STOPPED.")
										return
									end

									datastr = ""
									typestr = ""

									temparr = []

									req.params.each do |p|
										pn, pv, pt = p
										if pn
											if not pn.empty?
												if not pv or pv.empty?
													#TODO add value based on param name
													pv = "aaa"
												end
												#temparr << pn.to_s + "=" + Rex::Text.uri_encode(pv.to_s)
												temparr << pn.to_s + "=" + pv.to_s
											end
										else
											print_error("Blank parameter name. Form #{req.path}")
										end
									end

									datastr = temparr.join("&")	if (temparr and not temparr.empty?)

									modopts['METHOD'] = req.method.upcase
									modopts['PATH'] =  req.path
									if req.method.upcase == 'GET'
										modopts['QUERY'] = datastr
										modopts['DATA'] = ""
									end
									modopts['DATA'] = datastr if req.method.upcase == 'POST'
									modopts['TYPES'] = typestr

									#
									# TODO: Add method, headers, etc.
									#
									if (not usinginipath) or (usinginipath and req.path.match(inipathname))

										print_status "Path #{req.path}"
										#print_status("Query PATH #{modopts['PATH']}")
										#print_status("Query GET #{modopts['QUERY']}")
										#print_status("Query POST #{modopts['DATA']}")
										#print_status("Query TYPES #{typestr}")

										begin
											if execmod
												rpcnode = rpc_round_exec(xref[0],xref[1], modopts, self.njobs)
											end
										rescue ::Exception
											print_status(" >> Exception during launch from #{xref[0]}: #{$!}")
										end
									end
								end
							end

						rescue ::Exception
							print_status(" >> Exception from #{xref[0]}: #{$!}")
						end
					end
				end

				#
				# Handle modules that need to be after all tests, once.
				# Good place to have modules that analize the test results and/or
				# launch exploits.
				# :wmap_generic
				#
				print_status "\n=[ General testing ]="
				print_line "=" * sizeline

				idx = 0
				matches10.each_key do |xref|

					if self.masstop
						print_error("STOPPED.")
						return
					end

					# Module not part of profile or not match
					if not ( using_p and eprofile.include? xref[0].split('/').last ) or (using_m and xref[0].to_s.match(mname)) or (not using_m and not using_p)
						idx += 1


						begin
							# Module options hash
							modopts = Hash.new()

							#
							# The code is just a proof-of-concept and will be expanded in the future
							#

							print_status "Module #{xref[0]}"

							if (mode & wmap_expl != 0)

								#
								# For modules to have access to the global datastore
								# i.e. set -g DOMAIN test.com
								#
								self.framework.datastore.each do |gkey,gval|
									modopts[gkey]=gval
								end

								#
								# Parameters passed in hash xref
								#

								modopts['RHOST'] = selected_host
								modopts['RHOSTS'] = selected_host
								modopts['RPORT'] = selected_port.to_s
								modopts['SSL'] = selected_ssl
								modopts['VHOST'] = selected_vhost.to_s
								modopts['VERBOSE'] = moduleverbose
								modopts['ShowProgress'] = showprogress
								modopts['RunAsJob'] = jobify

								#
								# Run the plugins that only need to be
								# launched once.
								#

								begin
									if execmod
										rpcnode = rpc_round_exec(xref[0],xref[1], modopts, self.njobs)
									end
								rescue ::Exception
									print_status(" >> Exception during launch from #{xref[0]}: #{$!}")
								end
							end

						rescue ::Exception
							print_status(" >> Exception from #{xref[0]}: #{$!}")
						end
					end
				end


				if (mode & wmap_expl != 0)
					print_line "+" * sizeline

					if not self.runlocal
						if execmod
							rpc_list_nodes()
							print_status("Note: Use wmap_nodes -l to list node status for completion")
						end
					end

					print_line("Launch completed in #{(Time.now.to_f - stamp)} seconds.")
					print_line "+" * sizeline
				end

				print_status("Done.")
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
				tbl << [ idx.to_s, t[1][:vhost], t[1][:host], t[1][:port], t[1][:ssl], "\t"+t[1][:path].to_s ]
			}

			print_status tbl.to_s + "\n"
		end

		def delete_sites(wmap_index)
			idx  = 0
			to_del = {}
			# Rebuild the index from wmap_sites -l
			self.framework.db.hosts.each do |bdhost|
				bdhost.services.each do |serv|
					serv.web_sites.each do |web|
						# If the index of this site matches any deletion index,
						# add to our hash, saving the index for later output
						to_del[idx] = web if wmap_index.any? {|w| w.to_i == idx}
						idx += 1
					end
				end
			end
			to_del.each do |widx,wsite|
				if wsite.delete
					print_status("Deleted #{wsite.vhost} on #{wsite.service.host.address} at index #{widx}")
				else
					print_error("Could note delete {wsite.vhost} on #{wsite.service.host.address} at index #{widx}")
				end
			end
		end


		def view_sites
			# Clean temporary sites list
			self.lastsites = []

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
						'Proto',
						'# Pages',
						'# Forms',
					])

			idx  = 0
			if self.framework.db.active
				self.framework.db.hosts.each do |bdhost|
					bdhost.services.each do |serv|
						serv.web_sites.each do |web|
							c = web.web_pages.count
							f = web.web_forms.count
							tbl << [ idx.to_s, bdhost.address, web.vhost, serv.port, serv.name, c.to_s, f.to_s ]
							idx += 1

							turl = web.vhost + "," + serv.name + "://" +bdhost.address.to_s + ":" + serv.port.to_s + "/"
							self.lastsites << turl
						end
					end
				end
				print_status tbl.to_s + "\n"
			else
				print_status "No active database. Please connect a database and try again"
			end

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

			if not self.targets
				# First time targets are defined
				self.targets = Hash.new()
			end

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

				sites = serv.web_sites.where('vhost = ? and service_id = ?', vhost, serv.id)

				sites.each do |site|
					# Initial defaul path
					inipath = target.path
					if target.path.empty?
						inipath = '/'
					end

					#site.web_forms.find_all_by_path(target.path).each do |form|
						ckey = [ site.vhost, host.address, serv.port, inipath].join("|")

						if not self.targets[ckey]
							self.targets[ckey] = WebTarget.new
							self.targets[ckey].merge!({
								:vhost => site.vhost,
								:host  => host.address,
								:port  => serv.port,
								:ssl   => (serv.name == "https"),
								:path  => inipath
							})
							#self.targets[ckey][inipath] = []
						else
							print_status("Target already set in targets list.")
						end

						# Store the form object in the hash for this path
						#self.targets[ckey][inipath] << inipath
					#end
				end
			end
		end

		# Code by hdm. Modified two lines by et
		# lastsites contains a temporary array with vhost,url strings so the id can be
		# referenced in the array and prevent new sites added in the db to corrupt previous id list.
		def process_ids(idsstr)

			if !self.lastsites or self.lastsites.length == 0
				view_sites
				print_status ("Web sites ids. referenced from previous table.")
			end

			target_whitelist = []
			ids = idsstr.to_s.split(/,/)

			ids.each do |id|
				next if id.to_s.strip.empty?

				if id.to_i > self.lastsites.length
					print_error("Skipping id #{id}...")
				else
					target_whitelist << self.lastsites[id.to_i]
					print_status("Loading #{self.lastsites[id.to_i]}.")
				end
			end

			# Skip the DB entirely if no matches
			return if target_whitelist.length == 0

			if not self.targets
				self.targets = Hash.new()
			end

			target_whitelist.each do |ent|
				process_urls(ent)
			end
		end

		def view_site_tree(urlstr, md, ld)
			if not urlstr
				return
			end

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

			vsites = Hash.new()

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

				sites = serv.web_sites.where('vhost = ? and service_id = ?', vhost, serv.id)

				sites.each do |site|
					t = load_tree(site)
					print_tree(t,target.host,md,ld)
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

		def print_tree(tree, ip, maxlevel, limitlevel)
			initab = " " * 4
			indent = 6
			if  tree != nil and tree.depth <= maxlevel
				print initab + (" " * indent * tree.depth)
				if tree.depth > 0
					print "|"+("-" * (indent-1))+"/"
				end
				if tree.depth >= 0
					if tree.depth == 0
						print "[#{tree.name}] (#{ip})\n"+initab+(" " * indent)+"\n"

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
					print_tree(child,ip,maxlevel,limitlevel)
				end

			end
		end

		def signature(fpath,fquery)
			hsig = Hash.new()

			hsig = queryparse(fquery)

			#
			# Signature of the form ',p1,p2,pn' then to be appended to path: path,p1,p2,pn
			#

			sigstr = fpath + "," + hsig.map{|p| p[0].to_s}.join(",")
		end

		def queryparse(query)
			params = Hash.new()

			query.split(/[&;]/n).each do |pairs|
				key, value = pairs.split('=',2)
				if params.has_key?(key)
					#Error
				else
					params[key] = value
				end
			end
			params
		end

		def rpc_add_node(host,port,ssl,user,pass,bypass_exist)

			if not self.rpcarr
				self.rpcarr = Hash.new()
			end

			begin
				istr = "#{host}|#{port}|#{ssl}|#{user}|#{pass}"
				if self.rpcarr.has_key?(istr) and not bypass_exist and self.rpcarr[istr] != nil
					print_error("Connection already exists #{istr}")
				else
					begin
						temprpc = ::Msf::RPC::Client.new(
							:host => host,
							:port => port,
							:ssl => ssl
						)
					rescue
						print_error "Unable to connect"
						#raise ConnectionError
						return
					end

					res = temprpc.login( user , pass)

					if not res
						print_error("Unable to authenticate to #{host}:#{port}.")
						return
					else
						res = temprpc.call('core.version')
					end

					print_status("Connected to #{host}:#{port} [#{res['version']}].")
					self.rpcarr[istr] = temprpc
				end
			rescue
				print_error("Unable to connect")
			end
		end

		def local_module_exec(mod,mtype, opts, nmaxjobs)
			jobify = false

			modinst = framework.modules.create(mod)

			if(not modinst)
				print_error("Unknown module")
				return
			end

			sess = nil

			case mtype
				when 'auxiliary'
					Msf::Simple::Auxiliary.run_simple(modinst, {
						'Action'   => opts['ACTION'],
						'LocalOutput' => driver.output,
						'RunAsJob' => jobify,
						'Options'  => opts
					})
				when 'exploit'
					if not opts['PAYLOAD']
						opts['PAYLOAD'] = WmapCommandDispatcher::Exploit.choose_payload(modinst, opts['TARGET'])
					end

					sess = Msf::Simple::Exploit.exploit_simple(modinst, {
						'Payload'  => opts['PAYLOAD'],
						'Target'   => opts['TARGET'],
						'LocalOutput' => driver.output,
						'RunAsJob' => jobify,
						'Options'  => opts
					})
				else
					print_error("Wrong mtype.")
			end

			if sess
				if (jobify == false and sess.interactive?)
					print_line
					driver.run_single("sessions -q -i #{sess.sid}")
				else
					print_status("Session #{sess.sid} created in the background.")
				end
			end
		end

		def rpc_round_exec(mod,mtype, opts, nmaxjobs)

			res = nil
			idx = 0

			if active_rpc_nodes == 0
				if not self.runlocal
					print_error("All active nodes not working or removed")
					return
				end
				res = true
			else
				rpc_reconnect_nodes()
			end

			if self.masstop
				return
			end

			while not res
				if active_rpc_nodes == 0
					print_error("All active nodes not working or removed")
					return
				end

				#find the node with less jobs load.
				minjobs = nmaxjobs
				minconn = nil
				nid = 0
				self.rpcarr.each do |k,rpccon|
					if not rpccon
						print_error("Skipping inactive node #{nid} #{k}")
					else
						begin
							currentjobs = rpccon.call('job.list').length

							if currentjobs < minjobs
								minconn = rpccon
								minjobs = currentjobs
							end

							if currentjobs == nmaxjobs
								if self.nmaxdisplay == false
									print_error("Node #{nid} reached max number of jobs #{nmaxjobs}")
									print_error("Waiting for available node/slot...")
									self.nmaxdisplay = true
								end
							end
							#print_status("Node #{nid}   #currentjobs #{currentjobs} #min #{minjobs}")
						rescue
							print_error("Unable to connect. Node #{tarr[0]}:#{tarr[1]}")
							self.rpcarr[k]=nil

							if active_rpc_nodes == 0
								print_error("All active nodes ,not working or removed")
								return
							else
								print_error("Sending job to next node")
								next
							end
						end
					end
					nid += 1
				end

				if minjobs < nmaxjobs
					res=minconn.call('module.execute', mtype, mod, opts)
					self.nmaxdisplay = false
					#print_status(">>>#{res} #{mod}")

					if res
						if res.has_key?("job_id")
							return
						else
							print_error("Unable to execute module in node #{k} #{res}")
						end
					end
				else
					#print_status("Max number of jobs #{nmaxjobs} reached in node #{k}")
				end

				idx += 1
			end

			if self.runlocal and not self.masstop
				local_module_exec(mod,mtype, opts, nmaxjobs)
			end
		end

		def rpc_db_nodes(host,port,user,pass,name)
			rpc_reconnect_nodes()

			if active_rpc_nodes == 0
				print_error("No active nodes at this time")
				return
			end

			self.rpcarr.each do |k,v|
				if v
					res = v.call('db.driver',{:driver => 'postgresql'})
					res = v.call('db.connect',{:database => name, :host => host, :port => port, :username => user, :password => pass})
					res = v.call('db.status')

					if res['db'] == name
						print_status("db_connect #{res} #{host}:#{port} OK")
					else
						print_error("Error db_connect #{res}  #{host}:#{port}")
					end
				else
					print_error("No connection to node #{k}")
				end
			end
		end

		def rpc_reconnect_nodes()
			begin
				# Sucky 5 mins token timeout.

				idx = nil
				self.rpcarr.each do |k,rpccon|
					if rpccon
						idx = k
						begin
							currentjobs = rpccon.call('job.list').length
						rescue
							tarr = k.split("|")
							rflag = false

							res = rpccon.login(tarr[3],tarr[4])

							if res
								rflag = true
								print_error("Reauth to node #{tarr[0]}:#{tarr[1]}")
								break
							else
								raise ConnectionError
							end
						end
					end
				end
			rescue
				print_error("ERROR CONNECTING TO NODE.  Disabling #{idx} use wmap_nodes -a to reconnect")
				self.rpcarr[idx] = nil
				if active_rpc_nodes == 0
					print_error("No active nodes")
					self.masstop = true
				else
					#blah
				end
			end
		end

		def rpc_kill_node(i,j)

			if not i
				print_error("Nodes not defined")
				return
			end

			if not j
				print_error("Node jobs defined")
				return
			end

			rpc_reconnect_nodes()

			if active_rpc_nodes == 0
				print_error("No active nodes at this time")
				return
			end

			idx=0
			self.rpcarr.each do |k,rpccon|
				if idx == i.to_i or i.upcase == 'ALL'
					#begin
						if not rpccon
							print_error("No connection to node #{idx}")
						else
							n = rpccon.call('job.list')
							n.each do |id,name|
								if j==id.to_s or j.upcase == 'ALL'
									rpccon.call('job.stop',id)
									print_status("Node #{idx} Killed job id #{id} #{name}")
								end
							end
						end
					#rescue
					#	print_error("No connection")
					#end
				end
				idx += 1
			end
		end

		def rpc_view_jobs()
			indent = '     '

			rpc_reconnect_nodes()

			if active_rpc_nodes == 0
				print_error("No active nodes at this time")
				return
			end

			idx=0
			self.rpcarr.each do |k,rpccon|
				if not rpccon
					print_status("[Node ##{idx}: #{k} DISABLED/NO CONNECTION]")
				else

					arrk = k.split('|')
					print_status("[Node ##{idx}: #{arrk[0]} Port:#{arrk[1]} SSL:#{arrk[2]} User:#{arrk[3]}]")

					begin
						n = rpccon.call('job.list')

						tbl = Rex::Ui::Text::Table.new(
							'Indent'  => indent.length,
							'Header'  => 'Jobs',
							'Columns' =>
								[
									'Id',
									'Job name',
									'Target',
									'PATH',
								])

						n.each do |id,name|
							jinfo = rpccon.call('job.info',id)
							dstore = jinfo['datastore']
							tbl << [ id.to_s, name,dstore['VHOST']+":"+dstore['RPORT'],dstore['PATH']]
						end

						print_status tbl.to_s + "\n"

					rescue
						print_status("[Node ##{idx} #{k} DISABLED/NO CONNECTION]")
					end
				end
				idx += 1
			end
		end


		# Modified from http://stackoverflow.com/questions/946738/detect-key-press-non-blocking-w-o-getc-gets-in-ruby
		def quit?
			begin
				while c = driver.input.read_nonblock(1)
					print_status("Quited")
					return true if c == 'Q'
				end
				false
			rescue Errno::EINTR
				false
			rescue Errno::EAGAIN
				false
			rescue EOFError
				true
			end
		end

		def rpc_mon_nodes()
			# Pretty monitor

			color = self.opts["ConsoleDriver"].output.supports_color? rescue false

			colors = [
								 '%grn',
						 '%blu',
						 '%yel',
						 '%whi'
					 ]

			#begin
				loop do
					rpc_reconnect_nodes()

					idx = 0
					self.rpcarr.each do |k,rpccon|

						arrk = k.split('|')

						v = "NOCONN"
						n = 1
						c = '%red'

						if not rpccon
							v = "NOCONN"
							n = 1
							c = '%red'
						else
							begin
								v = ""
								c = '%blu'
							rescue
								v = "ERROR"
								c = '%red'
							end

							begin
								n = rpccon.call('job.list').length
								c = '%blu'
							rescue
								n = 1
								v = "NOCONN"
								c = '%red'
							end
						end

						#begin
							if not @stdio
								@stdio = Rex::Ui::Text::Output::Stdio.new
							end

							if color == true
								@stdio.auto_color
							else
								@stdio.disable_color
							end
							msg = "[#{idx}] #{"%bld#{c}||%clr"*n} #{n} #{v}\n"
							@stdio.print_raw(@stdio.substitute_colors(msg))

						#rescue
							#blah
						#end
						sleep(2)
						idx += 1
					end
				end
			#rescue
			#	print_status("End.")
			#end
		end

		def rpc_list_nodes()
			indent = '     '

			tbl = Rex::Ui::Text::Table.new(
				'Indent'  => indent.length,
				'Header'  => 'Nodes',
				'Columns' =>
					[
						'Id',
						'Host',
						'Port',
						'SSL',
						'User',
						'Pass',
						'Status',
						'#jobs',
					])

			idx=0

			rpc_reconnect_nodes()

			self.rpcarr.each do |k,rpccon|

				arrk = k.split('|')

				if not rpccon
					v = "NOCONN"
					n = ""
				else
					begin
						v = rpccon.call('core.version')['version']
					rescue
						v = "ERROR"
					end

					begin
						n = rpccon.call('job.list').length
					rescue
						n = ""
					end
				end

				tbl << [ idx.to_s, arrk[0], arrk[1], arrk[2], arrk[3], arrk[4], v, n]
				idx += 1
			end

			print_status tbl.to_s + "\n"
		end

		def active_rpc_nodes
			if self.rpcarr.length == 0
				return 0
			else
				idx = 0
				self.rpcarr.each do |k,conn|
					if conn
						idx += 1
					end
				end
				return idx
			end
		end

		def view_modules
			indent = '     '

			wmaptype = [:wmap_ssl,
						:wmap_server,
						:wmap_dir,
						:wmap_file,
						:wmap_unique_query,
						:wmap_query,
						:wmap_generic
						]

			if not self.wmapmodules
				load_wmap_modules(true)
			end

			wmaptype.each do |modt|

				tbl = Rex::Ui::Text::Table.new(
					'Indent'  => indent.length,
					'Header'  =>  modt.to_s,
					'Columns' =>
						[
							'Name',
							'OrderID',
						])

				idx = 0
				self.wmapmodules.each do |w|
					oid = w[3]
					if w[3] == 0xFFFFFF
						oid = ":last"
					end

					if w[2] == modt
						tbl << [w[0],oid]
						idx += 1
					end
				end

				print_status tbl.to_s + "\n"
			end
		end

		# Yes sorting hashes dont make sense but actually it does when you are enumerating one. And
		# sort_by of a hash returns an array so this is the reason for this ugly piece of code
		def sort_by_orderid(m)
			temphash=Hash.new()
			temparr=[]

			temparr = m.sort_by do |xref,v|
					xref[3]
			end

			temparr.each do |b|
				temphash[b[0]] = b[1]
			end
			temphash
		end

		# Load all wmap modules
		def load_wmap_modules(reload)
			if reload or not self.wmapmodules
				print_status("Loading wmap modules...")

				self.wmapmodules=[]

				idx = 0
				[ [ framework.auxiliary, 'auxiliary' ], [framework.exploits, 'exploit' ] ].each do |mtype|
					# Scan all exploit modules for matching references
					mtype[0].each_module do |n,m|
						e = m.new

						# Only include wmap_enabled plugins
						if e.respond_to?("wmap_enabled")
							penabled = e.wmap_enabled

							if penabled
								self.wmapmodules << [mtype[1]+'/'+n,mtype[1],e.wmap_type,e.orderid]
								idx += 1
							end
						end
					end
				end
				print_status("#{idx} wmap enabled modules loaded.")
			end
		end

		def view_vulns
			framework.db.hosts.each do |host|
				host.services.each do |serv|
					serv.web_sites.each do |site|
						site.web_vulns.each do |wv|
							print_status("+ [#{host.address}] (#{site.vhost}): #{wv.category} #{wv.path}")
							print_status("\t#{wv.name} #{wv.description}")
							print_status("\t#{wv.method} #{wv.proof}")
						end
					end
				end
			end
		end
	end

	class WebTarget < ::Hash
		def to_url
			proto = self[:ssl] ? "https" : "http"
			"#{proto}://#{self[:host]}:#{self[:port]}#{self[:path]}"
		end
	end


	def initialize(framework, opts)
		super

		color = self.opts["ConsoleDriver"].output.supports_color? rescue false

		wmapversion = '1.5.1'

		wmapbanner =  "%red\n.-.-.-..-.-.-..---..---.%clr\n"
		wmapbanner += "%red| | | || | | || | || |-'%clr\n"
		wmapbanner += "%red`-----'`-'-'-'`-^-'`-'%clr\n"
		wmapbanner += "[WMAP #{wmapversion}] ===  et [  ] metasploit.com 2012\n"

		if not @stdio
			@stdio = Rex::Ui::Text::Output::Stdio.new
		end

		if color == true
			@stdio.auto_color
		else
			@stdio.disable_color
		end

		@stdio.print_raw(@stdio.substitute_colors(wmapbanner))

		add_console_dispatcher(WmapCommandDispatcher)
		#print_status("#{wmapbanner}")
	end

	def cleanup
		remove_console_dispatcher('wmap')
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
