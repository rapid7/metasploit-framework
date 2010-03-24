#!/usr/bin/env ruby
#
# This plugin provides integration with Rapid7 NeXpose
#

require 'rapid7/nexpose'

module Msf
class Plugin::Nexpose < Msf::Plugin
	class NexposeCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def name
			"NeXpose"
		end

		def commands
			{
				'nexpose_connect'        => "Connect to a running NeXpose instance ( user:pass@host[:port] )",
				'nexpose_activity'       => "Display any active scan jobs on the NeXpose instance",

				'nexpose_scan'           => "Launch a NeXpose scan against a specific IP range and import the results",
				'nexpose_discover'       => "Launch a scan but only perform host and minimal service discovery",
				'nexpose_exhaustive'     => "Launch a scan covering all TCP ports and all authorized safe checks",
				'nexpose_dos'            => "Launch a scan that includes checks that can crash services and devices (caution)",

				'nexpose_disconnect'     => "Disconnect from an active NeXpose instance",

				# TODO:
				# nexpose_stop_scan
			}
		end

		def nexpose_verify
			if ! @nsc
				print_error("No active NeXpose instance has been configured, please use 'nexpose_connect'")
				return false
			end

			if ! (framework.db and framework.db.usable)
				print_error("No database has been configured, please use db_create/db_connect first")
				return false
			end

			true
		end

		def cmd_nexpose_connect(*args)

			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status("Usage: ")
				print_status("       nexpose_connect username:password@host[:port] <ssl-confirm>")
				print_status("        -OR- ")
				print_status("       nexpose_connect username password host port <ssl-confirm>")
				return
			end

			user = pass = host = port = sslv = nil

			case args.length
			when 1,2
				cred,targ = args[0].split('@', 2)
				user,pass = cred.split(':', 2)
				targ ||= '127.0.0.1:3780'
				host,port = targ.split(':', 2)
				port ||= '3780'
				sslv = args[1]
			when 4,5
				user,pass,host,port,sslv = args
			else
				print_status("Usage: ")
				print_status("       nexpose_connect username:password@host[:port] <ssl-confirm>")
				print_status("        -OR- ")
				print_status("       nexpose_connect username password host port <ssl-confirm>")
				return
			end


			if ! ((user and user.length > 0) and (host and host.length > 0) and (port and port.length > 0 and port.to_i > 0) and (pass and pass.length > 0))
				print_status("Usage: ")
				print_status("       nexpose_connect username:password@host[:port] <ssl-confirm>")
				print_status("        -OR- ")
				print_status("       nexpose_connect username password host port <ssl-confirm>")
				return
			end

			if(host != "localhost" and host != "127.0.0.1" and sslv != "ok")
				print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
				print_error("         with the ability to man-in-the-middle the NeXpose traffic to capture the NeXpose")
				print_error("         credentials. If you are running this on a trusted network, please pass in 'ok'")
				print_error("         as an additional parameter to this command.")
				return
			end

			# Wrap this so a duplicate session doesnt prevent a new login
			begin
			cmd_nexpose_disconnect
			rescue ::Interrupt
				raise $!
			rescue ::Exception
			end

			begin
				print_status("Connecting to NeXpose instance at #{host}:#{port} with username #{user}...")
				nsc = ::Nexpose::Connection.new(host, user, pass, port)
				nsc.login
			rescue ::Nexpose::APIError => e
				print_error("Connection failed: #{e.reason}")
				return
			end

			@nsc = nsc
		end

		def cmd_nexpose_activity(*args)
			return if not nexpose_verify
			scans = @nsc.scan_activity || []
			case scans.length
			when 0
				print_status("There are currently no active scan jobs on this NeXpose instance")
			when 1
				print_status("There is 1 active scan job on this NeXpose instance")
			else
				print_status("There are currently #{scans.length} active scan jobs on this NeXpose instance")
			end

			scans.each do |scan|
				print_status("    Scan ##{scan[:scan_id]} is running on Engine ##{scan[:engine_id]} against site ##{scan[:site_id]} since #{scan[:start_time].to_s}")
			end
		end

		def cmd_nexpose_discover(*args)
			args << "-h" if args.length == 0
			args << "-t"
			args << "aggressive-discovery"
			cmd_nexpose_scan(*args)
		end

		def cmd_nexpose_exhaustive(*args)
			args << "-h" if args.length == 0
			args << "-t"
			args << "exhaustive-audit"
			cmd_nexpose_scan(*args)
		end

		def cmd_nexpose_dos(*args)
			args << "-h" if args.length == 0
			args << "-t"
			args << "dos-audit"
			cmd_nexpose_scan(*args)
		end

		def cmd_nexpose_scan(*args)

			opts = Rex::Parser::Arguments.new(
				"-h"   => [ false,  "This help menu"],
				"-t"   => [ true,   "The scan template to use (default:pentest-audit options:full-audit,exhaustive-audit,discovery,aggressive-discovery,dos-audit)"],
				"-c"   => [ true,   "Specify credentials to use against these targets (format is type:user:pass[@host[:port]]"],
				"-n"   => [ true,   "The maximum number of IPs to scan at a time (default is 32)"],
				"-s"   => [ true,   "The directory to store the raw XML files from the NeXpose instance (optional)"],
				"-P"   => [ false,  "Leave the scan data on the server when it completes (this counts against the maximum licensed IPs)"],
				"-v"   => [ false,  "Display diagnostic information about the scanning process"],
				"-x"   => [ false,  "Automatically launch all exploits by matching reference after the scan completes (unsafe)"],
				"-X"   => [ false,  "Automatically launch all exploits by matching reference and port after the scan completes (unsafe)"],
				"-R"   => [ true,   "Specify a minimum exploit rank to use for automated exploitation"],
				"-d"   => [ false,  "Scan hosts based on the contents of the existing database"],
				"-I"   => [ true,   "Only scan systems with an address within the specified range"],
				"-E"   => [ true,   "Exclude hosts in the specified range from the scan"]
			)

			opt_template  = "pentest-audit"
			opt_maxaddrs  = 32
			opt_monitor   = false
			opt_verbose   = false
			opt_savexml   = nil
			opt_preserve  = false
			opt_autopwn   = false
			opt_rescandb  = false
			opt_addrinc   = nil
			opt_addrexc   = nil
			opt_scanned   = []
			opt_minrank   = "manual"
			opt_credentials = []

			opt_ranges    = []
			report_format = "ns-xml"

			opts.parse(args) do |opt, idx, val|
				case opt
				when "-h"
					print_line("Usage: nexpose_scan [options] <Target IP Ranges>")
					print_line(opts.usage)
					return
				when "-t"
					opt_template = val
				when "-n"
					opt_maxaddrs = val.to_i
				when "-s"
					opt_savexml = val
				when "-c"
					if (val =~ /^([^:]+):([^:]+):([^:]+)/)
						type, user, pass = [ $1, $2, $3 ]
						newcreds = Nexpose::AdminCredentials.new
						newcreds.setCredentials(type, nil, nil, user, pass, nil)
						opt_credentials << newcreds
					else
						print_error("Unrecognized NeXpose scan credentials: #{val}")
						return
					end
				when "-v"
					opt_verbose = true
				when "-P"
					opt_preserve = true
				when "-X"
					opt_autopwn = "-p -x"
				when "-x"
					opt_autopwn = "-x" unless opt_autopwn
				when "-d"
					opt_rescandb = true
				when '-I'
					opt_addrinc = OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(val)
				when '-E'
					opt_addrexc = OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(val)
				when '-R'
					opt_minrank = val
				else
					opt_ranges << val
				end
			end

			return if not nexpose_verify

			# Include all database hosts as scan targets if specified
			if(opt_rescandb)
				print_status("Loading scan targets from the active database...") if opt_verbose
				framework.db.hosts.each do |host|
					next if host.state != ::Msf::HostState::Alive
					opt_ranges << host.address
				end
			end

			opt_ranges = opt_ranges.join(' ')

			if(opt_ranges.strip.empty?)
				print_line("Usage: nexpose_scan [options] <Target IP Ranges>")
				print_line(opts.usage)
				return
			end

			if(opt_verbose)
				print_status("Creating a new scan using template #{opt_template} and #{opt_maxaddrs} concurrent IPs against #{opt_ranges}")
			end

			range_inp = ::Msf::OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(opt_ranges)
			range     = ::Rex::Socket::RangeWalker.new(range_inp)
			include_range = opt_addrinc ? ::Rex::Socket::RangeWalker.new(opt_addrinc) : nil
			exclude_range = opt_addrexc ? ::Rex::Socket::RangeWalker.new(opt_addrexc) : nil

			completed = 0
			total     = range.num_ips
			count     = 0

			print_status("Scanning #{total} addresses with template #{opt_template} in sets of #{opt_maxaddrs}")

			while(completed < total)
				count    += 1
				queue     = []

				while(ip = range.next_ip and queue.length < opt_maxaddrs)

					if(exclude_range and exclude_range.include?(ip))
						print_status(" >> Skipping host #{ip} due to exclusion") if opt_verbose
						next
					end

					if(include_range and ! include_range.include?(ip))
						print_status(" >> Skipping host #{ip} due to inclusion filter") if opt_verbose
						next
					end

					opt_scanned << ip
					queue << ip
				end

				break if queue.empty?
				print_status("Scanning #{queue[0]}-#{queue[-1]}...") if opt_verbose

				msfid = Time.now.to_i

				# Create a temporary site
				site = Nexpose::Site.new(@nsc)
				site.setSiteConfig("Metasploit-#{msfid}", "Autocreated by the Metasploit Framework")
				queue.each do |ip|
					site.site_config.addHost(Nexpose::IPRange.new(ip))
				end
				site.site_config._set_scanConfig(Nexpose::ScanConfig.new(-1, "tmp", opt_template))
				opt_credentials.each do |c|
					site.site_config.addCredentials(c)
				end
				site.saveSite()

				print_status(" >> Created temporary site ##{site.site_id}") if opt_verbose

				# Configure reporting
				report = Nexpose::ReportConfig.new(@nsc)
				report.set_name("Metasploit Export #{msfid}")
				report.set_template_id(opt_template)
				report.set_format(report_format)
				report.addFilter("SiteFilter",site.site_id)
				report.set_generate_after_scan(1)
				report.set_storeOnServer(1)
				report.saveReport()

				print_status(" >> Created temporary report configuration ##{report.config_id}") if opt_verbose

				# Run the scan
				res = site.scanSite()
				sid = res[:scan_id]

				print_status(" >> Scan has been launched with ID ##{sid}") if opt_verbose

				rep = true
				begin
				prev = nil
				while(true)
					info = @nsc.scan_statistics(sid)
					break if info[:summary]['status'] != "running"
					stat = "Found #{info[:nodes]['live']} devices and #{info[:nodes]['dead']} unresponsive"
					if(stat != prev)
						print_status(" >> #{stat}") if opt_verbose
					end
					prev = stat
					select(nil, nil, nil, 5.0)
				end
				print_status(" >> Scan has been completed with ID ##{sid}") if opt_verbose
				rescue ::Interrupt
					rep = false
					print_status(" >> Terminating scan ID ##{sid} due to console interupt") if opt_verbose
					@nsc.scan_stop(sid)
					break
				end

				# Wait for the automatic report generation to complete
				if(rep)
					print_status(" >> Waiting on the report to generate...") if opt_verbose
					url = nil
					while(! url)
						url = @nsc.report_last(report.config_id)
						select(nil, nil, nil, 1.0)
					end

					print_status(" >> Downloading the report data from NeXpose...") if opt_verbose
					data = @nsc.download(url)

					if(opt_savexml)
						::FileUtils.mkdir_p(opt_savexml)
						path = File.join(opt_savexml, "nexpose-#{msfid}-#{count}.xml")
						print_status(" >> Saving scan data into #{path}") if opt_verbose
						::File.open(path, "wb") do |fd|
							fd.write(data)
						end
					end

					process_nexpose_data(report_format, data)
				end

				if ! opt_preserve
					print_status(" >> Deleting the temporary site and report...") if opt_verbose
					@nsc.site_delete(site.site_id)
				end
			end

			print_status("Completed the scan of #{total} addresses")

			if(opt_autopwn)
				print_status("Launching an automated exploitation session")
				driver.run_single("db_autopwn -q -r -e -t #{opt_autopwn} -R #{opt_minrank} -I #{opt_scanned.join(",")}")
			end
		end

		def cmd_nexpose_disconnect(*args)
			@nsc.logout if @nsc
			@nsc = nil
		end

		def process_nexpose_data(fmt, data)
			case fmt
			when 'raw-xml'
				framework.db.import_nexpose_rawxml(data)
			when 'ns-xml'
				framework.db.import_nexpose_simplexml(data)
			else
				print_error("Unsupported NeXpose data format: #{fmt}")
			end
		end

        #
        # NeXpose vuln lookup
        #
        def nexpose_vuln_lookup(doc, vid, refs, host, serv=nil)
            doc.elements.each("/NexposeReport/VulnerabilityDefinitions/vulnerability[@id = '#{vid}']]") do |vulndef|

                title = vulndef.attributes['title']
                pciSeverity = vulndef.attributes['pciSeverity']
                cvss_score = vulndef.attributes['cvssScore']
                cvss_vector = vulndef.attributes['cvssVector']

                vulndef.elements['references'].elements.each('reference') do |ref|
                    if ref.attributes['source'] == 'BID'
                        refs[ 'BID-' + ref.text ] = true
                    elsif ref.attributes['source'] == 'CVE'
                        # ref.text is CVE-$ID
                        refs[ ref.text ] = true
                    elsif ref.attributes['source'] == 'MS'
                        refs[ 'MSB-MS-' + ref.text ] = true
                    end
                end

                refs[ 'NEXPOSE-' + vid.downcase ] = true

                vuln = framework.db.find_or_create_vuln(
					:host => host,
					:service => serv,
					:name => 'NEXPOSE-' + vid.downcase,
					:data => title)

                rids = []
                refs.keys.each do |r|
                    rids << framework.db.find_or_create_ref(:name => r)
                end

                vuln.refs << (rids - vuln.refs)
            end
        end

	end

	#
	# Plugin initialization
	#

	def initialize(framework, opts)
		super

		add_console_dispatcher(NexposeCommandDispatcher)
		banner = ["0a205f5f5f5f202020202020202020202020205f20202020205f205f5f5f5f5f2020205f2020205f20202020205f5f20205f5f2020202020202020202020202020202020202020200a7c20205f205c205f5f205f205f205f5f20285f29205f5f7c207c5f5f5f20207c207c205c207c207c205f5f5f5c205c2f202f5f205f5f2020205f5f5f20205f5f5f20205f5f5f200a7c207c5f29202f205f60207c20275f205c7c207c2f205f60207c20202f202f20207c20205c7c207c2f205f205c5c20202f7c20275f205c202f205f205c2f205f5f7c2f205f205c0a7c20205f203c20285f7c207c207c5f29207c207c20285f7c207c202f202f2020207c207c5c20207c20205f5f2f2f20205c7c207c5f29207c20285f29205c5f5f205c20205f5f2f0a7c5f7c205c5f5c5f5f2c5f7c202e5f5f2f7c5f7c5c5f5f2c5f7c2f5f2f202020207c5f7c205c5f7c5c5f5f5f2f5f2f5c5f5c202e5f5f2f205c5f5f5f2f7c5f5f5f2f5c5f5f5f7c0a20202020202020202020207c5f7c20202020202020202020202020202020202020202020202020202020202020202020207c5f7c202020202020202020202020202020202020200a0a0a"].pack("H*")

		if ! (Rex::Compat.is_windows or Rex::Compat.is_cygwin)
			banner = ["202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a20e29684e29684e29684202020e29684e29684202020202020202020202020e29684e29684e296842020e29684e29684e2968420202020202020202020202020202020202020202020202020202020202020202020202020202020200a20e29688e29688e29688202020e29688e2968820202020202020202020202020e29688e2968820e29684e29688e296882020202020202020202020202020202020202020202020202020202020202020202020202020202020200a20e29688e29688e29680e296882020e29688e29688202020e29684e29688e29688e29688e29688e296842020202020e29688e29688e29688e2968820202020e29688e29688e29684e29688e29688e29688e2968420202020e29684e29688e29688e29688e29688e29684202020e29684e29684e29688e29688e29688e29688e29688e29684202020e29684e29688e29688e29688e29688e2968420200a20e29688e2968820e29688e2968820e29688e296882020e29688e29688e29684e29684e29684e29684e29688e296882020202020e29688e296882020202020e29688e29688e296802020e29680e29688e296882020e29688e29688e296802020e29680e29688e296882020e29688e29688e29684e29684e29684e2968420e296802020e29688e29688e29684e29684e29684e29684e29688e29688200a20e29688e296882020e29688e29684e29688e296882020e29688e29688e29680e29680e29680e29680e29680e2968020202020e29688e29688e29688e2968820202020e29688e2968820202020e29688e296882020e29688e2968820202020e29688e29688202020e29680e29680e29680e29680e29688e29688e296842020e29688e29688e29680e29680e29680e29680e29680e29680200a20e29688e29688202020e29688e29688e296882020e29680e29688e29688e29684e29684e29684e29684e29688202020e29688e296882020e29688e29688202020e29688e29688e29688e29684e29684e29688e29688e296802020e29680e29688e29688e29684e29684e29688e29688e296802020e29688e29684e29684e29684e29684e29684e29688e296882020e29680e29688e29688e29684e29684e29684e29684e29688200a20e29680e29680202020e29680e29680e2968020202020e29680e29680e29680e29680e29680202020e29680e29680e296802020e29680e29680e296802020e29688e2968820e29680e29680e29680202020202020e29680e29680e29680e296802020202020e29680e29680e29680e29680e29680e296802020202020e29680e29680e29680e29680e2968020200a20202020202020202020202020202020202020202020202020202020202020e29688e29688202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a"].pack("H*")
		end
		print(banner)
		print_status("NeXpose integration has been activated")
	end

	def cleanup
		remove_console_dispatcher('NeXpose')
	end

	def name
		"nexpose"
	end

	def desc
		"Integrates with the Rapid7 NeXpose vulnerability management product"
	end
end
end

