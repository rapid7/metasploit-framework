#!/usr/bin/env ruby
#
# This plugin provides integration with Rapid7 NeXpose
#

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

#
# The NeXpose API
#

#
# WARNING! This code makes an SSL connection to the NeXpose server, but does NOT
#          verify the certificate at this time. This can be a security issue if
#          an attacker is able to man-in-the-middle the connection between the
#          Metasploit console and the NeXpose server. In the common case of
#          running NeXpose and Metasploit on the same host, this is a low risk.
#

#
# WARNING! This code is still rough and will go through a number of major changes
#          before the final release. Please do not build any tools using this API
#          unless you are prepared to rewrite them in the near future.
#

require 'date'
require 'rexml/document'
require 'net/https'
require 'net/http'
require 'uri'

module Nexpose

class APIError < ::RuntimeError
	attr_accessor :req, :reason
	def initialize(req, reason = '')
		self.req = req
		self.reason = reason
	end
	def to_s
		"NexposeAPI: #{self.reason}"
	end
end

module XMLUtils
	def parse_xml(xml)
		::REXML::Document.new(xml.to_s)
	end
end

class APIRequest
	include XMLUtils

	attr_reader :http
	attr_reader :uri
	attr_reader :headers
	attr_reader :retry_count
	attr_reader :time_out
	attr_reader :pause

	attr_reader :req
	attr_reader :res
	attr_reader :sid
	attr_reader :success

	attr_reader :error
	attr_reader :trace

	def initialize(req, url)
		@retry_count = 0
		@retry_count_max = 10
		@time_out = 30
		@pause = 2
		@req = req
		@uri = URI.parse(url)
		@http = Net::HTTP.new(@uri.host, @uri.port)
		@http.use_ssl = true
		@http.verify_mode = OpenSSL::SSL::VERIFY_NONE   # XXX: security issue
		@headers = {'Content-Type' => 'text/xml'}
		@success = false
	end

	def execute
		begin
		resp, data = @http.post(@uri.path, @req, @headers)
		@res = parse_xml(data)

		if(not @res.root)
			@error = "NeXpose service returned invalid XML"
			return @sid
		end

		@sid = attributes['session-id']

		if(attributes['success'] and attributes['success'].to_i == 1)
			@success = true
		else
			@success = false
			@res.elements.each('//Failure/Exception') do |s|
				s.elements.each('message') do |m|
					@error = m.text
				end
				s.elements.each('stacktrace') do |m|
					@trace = m.text
				end
			end
		end
		rescue ::Interrupt
			@error = "received a user interrupt"
		rescue ::Timeout::Error, ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::EADDRNOTAVAIL
			@error = "NeXpose host is unreachable"
		rescue ::Errno::ECONNRESET,::Errno::ECONNREFUSED,::Errno::ENOTCONN,::Errno::ECONNABORTED
			@error = "NeXpose service is not available"
		end

		if ! (@success or @error)
			@error = "NeXpose service returned an unrecognized response"
		end

		@sid
	end

	def attributes(*args)
		return if not @res.root
		@res.root.attributes(*args)
	end

	def self.execute(url,req)
		obj = self.new(req,url)
		obj.execute
		if(not obj.success)
			raise APIError.new(obj, "Action failed: #{obj.error}")
		end
		obj
	end

end

module NexposeAPI

	def make_xml(name, opts={})
		xml = REXML::Element.new(name)
		if(@session_id)
			xml.attributes['session-id'] = @session_id
		end

		opts.keys.each do |k|
			xml.attributes[k] = opts[k]
		end

		xml
	end

	def scan_stop(param)
		r = execute(make_xml('ScanStopRequest', { 'scan-id' => param }))
		r.success
	end

	def scan_status(param)
		r = execute(make_xml('ScanStatusRequest', { 'scan-id' => param }))
		r.success ? r.attributes['status'] : nil
	end

	def scan_activity
		r = execute(make_xml('ScanActivityRequest', { }))
		if(r.success)
			res = []
			r.res.elements.each("//ScanSummary") do |scan|
				res << {
					:scan_id    => scan.attributes['scan-id'].to_i,
					:site_id    => scan.attributes['site-id'].to_i,
					:engine_id  => scan.attributes['engine-id'].to_i,
					:status     => scan.attributes['status'].to_s,
					:start_time => Date.parse(scan.attributes['startTime'].to_s).to_time
				}
			end
			return res
		else
			return false
		end
	end

	def scan_statistics(param)
		r = execute(make_xml('ScanStatisticsRequest', {'scan-id' => param }))
		if(r.success)
			res = {}
			r.res.elements.each("//ScanSummary/nodes") do |node|
				res[:nodes] = {}
				node.attributes.keys.each do |k|
					res[:nodes][k] = node.attributes[k].to_i
				end
			end
			r.res.elements.each("//ScanSummary/tasks") do |task|
				res[:task] = {}
				task.attributes.keys.each do |k|
					res[:task][k] = task.attributes[k].to_i
				end
			end
			r.res.elements.each("//ScanSummary/vulnerabilities") do |vuln|
				res[:vulns] ||= {}
				k = vuln.attributes['status'] + (vuln.attributes['severity'] ? ("-" + vuln.attributes['severity']) : '')
				res[:vulns][k] = vuln.attributes['count'].to_i
			end
			r.res.elements.each("//ScanSummary") do |summ|
				res[:summary] = {}
				summ.attributes.keys.each do |k|
					res[:summary][k] = summ.attributes[k]
					if (res[:summary][k] =~ /^\d+$/)
						res[:summary][k] = res[:summary][k].to_i
					end
				end
			end
			return res
		else
			return false
		end
	end

	def report_generate(param)
		r = execute(make_xml('ReportGenerateRequest', { 'report-id' => param }))
		r.success
	end

	def report_last(param)
		r = execute(make_xml('ReportHistoryRequest', { 'reportcfg-id' => param }))
		res = nil
		if(r.success)
			stk = []
			r.res.elements.each("//ReportSummary") do |rep|
				stk << [ rep.attributes['id'].to_i, rep.attributes['report-URI'] ]
			end
			if (stk.length > 0)
				stk.sort!{|a,b| b[0] <=> a[0]}
				res = stk[0][1]
			end
		end
		res
	end

	def report_history(param)
		execute(make_xml('ReportHistoryRequest', { 'reportcfg-id' => param }))
	end

	def report_config_delete(param)
		r = execute(make_xml('ReportDeleteRequest', { 'reportcfg-id' => param }))
		r.success
	end

	def report_delete(param)
		r = execute(make_xml('ReportDeleteRequest', { 'report-id' => param }))
		r.success
	end

	def site_delete(param)
		r = execute(make_xml('SiteDeleteRequest', { 'site-id' => param }))
		r.success
	end

	def device_delete(param)
		r = execute(make_xml('DeviceDeleteRequest', { 'site-id' => param }))
		r.success
	end

	def asset_group_delete(connection, id, debug = false)
		r = execute(make_xml('AssetGroupDeleteRequest', { 'group-id' => param }))
		r.success
	end

end

# === Description
# Object that represents a connection to a NeXpose Security Console.
#
# === Examples
#   # Create a new Nexpose Connection on the default port
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#
#   # Login to NSC and Establish a Session ID
#   nsc.login()
#
#   # Check Session ID
#   if (nsc.session_id)
#       puts "Login Successful"
#   else
#       puts "Login Failure"
#   end
#
#   # //Logout
#   logout_success = nsc.logout()
#   if (! logout_success)
#       puts "Logout Failure" + "<p>" + nsc.error_msg.to_s
#   end
#
class Connection
	include XMLUtils
	include NexposeAPI

	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# Session ID of this connection
	attr_reader :session_id
	# The hostname or IP Address of the NSC
	attr_reader :host
	# The port of the NSC (default is 3780)
	attr_reader :port
	# The username used to login to the NSC
	attr_reader :username
	# The password used to login to the NSC
	attr_reader :password
	# The URL for communication
	attr_reader :url

	# Constructor for Connection
	def initialize(ip, user, pass, port = 3780)
		@host = ip
		@port = port
		@username = user
		@password = pass
		@session_id = nil
		@error = false
		@url = "https://#{@host}:#{@port}/api/1.1/xml"
	end

	# Establish a new connection and Session ID
	def login
		r = execute(make_xml('LoginRequest', { 'sync-id' => 0, 'password' => @password, 'user-id' => @username }))
		if(r.success)
			@session_id = r.sid
			return true
		end
		raise APIError.new(r, 'Login failed')
	end

	# Logout of the current connection
	def logout
		r = execute(make_xml('LogoutRequest', {'sync-id' => 0}))
		if(r.success)
			return true
		end
		raise APIError.new(r, 'Logout failed')
	end

	# Execute an API request
	def execute(xml)
		APIRequest.execute(url,xml.to_s)
	end

	# Download a specific URL
	def download(url)
		uri = URI.parse(url)
		http = Net::HTTP.new(@host, @port)
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE            # XXX: security issue
		headers = {'Cookie' => "nexposeCCSessionID=#{@session_id}"}
		resp, data = http.get(uri.path, headers)
		data
	end
end

# === Description
# Object that represents a listing of all of the sites available on an NSC.
#
# === Example
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc->login();
#
#   # Get Site Listing
#   sitelisting = SiteListing.new(nsc)
#
#   # Enumerate through all of the SiteSummaries
#   sitelisting.sites.each do |sitesummary|
#       # Do some operation on each site
#   end
#
class SiteListing
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# Array containing SiteSummary objects for each site in the connection
	attr_reader :sites
	# The number of sites
	attr_reader :site_count

	# Constructor
	# SiteListing (connection)
	def initialize(connection)
		@sites = []

		@connection = connection

		r = @connection.execute('<SiteListingRequest session-id="' + @connection.session_id.to_s + '"/>')

		if (r.success)
			parse(r.res)
		else
			raise APIError.new(r, "Failed to get site listing")
		end
	end

	def parse(r)
		r.elements.each('SiteListingResponse/SiteSummary') do |s|
			site_summary = SiteSummary.new(
				s.attributes['id'].to_s,
				s.attributes['name'].to_s,
				s.attributes['description'].to_s,
				s.attributes['riskfactor'].to_s
			)
			@sites.push(site_summary)
		end
		@site_count = @sites.length
	end
end

# === Description
# Object that represents the summary of a NeXpose Site.
#
class SiteSummary
	# The Site ID
	attr_reader :id
	# The Site Name
	attr_reader :site_name
	# A Description of the Site
	attr_reader :description
	# User assigned risk multiplier
	attr_reader :riskfactor

	# Constructor
	# SiteSummary(id, site_name, description, riskfactor = 1)
	def initialize(id, site_name, description, riskfactor = 1)
		@id = id
		@site_name = site_name
		@description = description
		@riskfactor = riskfactor
	end

	def _set_id(id)
		@id = id
	end
end

# === Description
# Object that represents a single IP address or an inclusive range of IP addresses. If to is nil then the from field will be used to specify a single IP Address only.
#
class IPRange
	# Start of Range *Required
	attr_reader :from;
	# End of Range *Optional (If Null then IPRange is a single IP Address)
	attr_reader :to;

	def initialize(from, to = nil)

		@from = from
		@to = to

	end
end

# === Description
# Object that represents a hostname to be added to a site.
class HostName

	# The hostname
	attr_reader :hostname

	def initialize(hostname)

		@hostname = hostname

	end
end

# === Description
# Object that represents the configuration of a Site. This object is automatically created when a new Site object is instantiated.
#
class SiteConfig
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The Site ID
	attr_reader :site_id
	# The Site Name
	attr_reader :site_name
	# A Description of the Site
	attr_reader :description
	# User assigned risk multiplier
	attr_reader :riskfactor
	# Array containing ((IPRange|HostName)*)
	attr_reader :hosts
	# Array containing (AdminCredentials*)
	attr_reader :credentials
	# Array containing ((SmtpAlera|SnmpAlert|SyslogAlert)*)
	attr_reader :alerts
	# ScanConfig object which holds Schedule and ScanTrigger Objects
	attr_reader :scanConfig

	def initialize()
		@xml_tag_stack = Array.new()
		@hosts = Array.new()
		@credentials = Array.new()
		@alerts = Array.new()
		@error = false
	end

	# Adds a new host to the hosts array
	def addHost(host)
		@hosts.push(host)
	end

	# Adds a new alert to the alerts array
	def addAlert(alert)
		@alerts.push(alert)
	end

	# Adds a new set of credentials to the credentials array
	def addCredentials(credential)
		@credentials.push(credential)
	end

	# TODO
	def getSiteConfig(connection,site_id)
		@connection = connection
		@site_id = site_id

		r = APIRequest.execute(@connection.url,'<SiteConfigRequest session-id="' + @connection.session_id + '" site-id="' + @site_id + '"/>')
		parse(r.res)
	end

	def _set_site_id(site_id)
		@site_id = site_id
	end

	def _set_site_name(site_name)
		@site_name = site_name
	end

	def _set_description(description)
		@description = description
	end

	def _set_riskfactor(riskfactor)
		@riskfactor = riskfactor
	end

	def _set_scanConfig(scanConfig)
		@scanConfig = scanConfig
	end

	def _set_connection(connection)
		@connection = connection
	end
=begin
<SiteConfigResponse success='1'>
<Site name='Site1' id='243' description='' riskfactor='1.0'>
<Hosts>
<range from='127.0.0.1'/>
</Hosts>
<Credentials>
</Credentials>
<Alerting>
</Alerting>
<ScanConfig configID='243' name='Full audit' configVersion='3' engineID='2' templateID='full-audit'>
<Schedules>
</Schedules>
<ScanTriggers>
</ScanTriggers>
</ScanConfig>
</Site>

=end

	def parse(response)
		response.elements.each('SiteConfigResponse/Site') do |s|
			@site_id = s.attributes['id']
			@site_name = s.attributes['name']
			@description = s.attributes['description']
			@riskfactor = s.attributes['riskfactor']
			s.elements.each('Hosts/range') do |r|
				@hosts.push(IPRange.new(r.attributes['from'],r.attributes['to']))
			end
			s.elements.each('ScanConfig') do |c|
				@scanConfig = ScanConfig.new(c.attributes['configID'],
											c.attributes['name'],
											c.attributes['configVersion'],
											c.attributes['templateID'])
				s.elements.each('Schedule') do |schedule|
					schedule = new Schedule(schedule.attributes["type"], schedule.attributes["interval"], schedule.attributes["start"], schedule.attributes["enabled"])
					@scanConfig.addSchedule(schedule)
				end
			end

			s.elements.each('Alerting/Alert') do |a|

				a.elements.each('smtpAlert') do |smtp|
					smtp_alert = SmtpAlert.new(a.attributes["name"], smtp.attributes["sender"], smtp.attributes["limitText"], a.attributes["enabled"])

					smtp.elements.each('recipient') do |recipient|
						smtp_alert.addRecipient(recipient.text)
					end
					@alerts.push(smtp_alert)
				end

				a.elements.each('snmpAlert') do |snmp|
					snmp_alert = SnmpAlert.new(a.attributes["name"], snmp.attributes["community"], snmp.attributes["server"], a.attributes["enabled"])
					@alerts.push(snmp_alert)
				end
				a.elements.each('syslogAlert') do |syslog|
					syslog_alert = SyslogAlert.new(a.attributes["name"], syslog.attributes["server"], a.attributes["enabled"])
					@alerts.push(syslog_alert)
				end

				a.elements.each('vulnFilter') do |vulnFilter|

					#vulnfilter = new VulnFilter.new(a.attributes["typemask"], a.attributes["severityThreshold"], $attrs["MAXALERTS"])
					# Pop off the top alert on the stack
					#$alert = @alerts.pop()
					# Add the new recipient string to the Alert Object
					#$alert.setVulnFilter($vulnfilter)
					# Push the alert back on to the alert stack
					#array_push($this->alerts, $alert)
				end

				a.elements.each('scanFilter') do |scanFilter|
					#<scanFilter scanStop='0' scanFailed='0' scanStart='1'/>
					#scanfilter = ScanFilter.new(scanFilter.attributes['scanStop'],scanFilter.attributes['scanFailed'],scanFilter.attributes['scanStart'])
					#alert = @alerts.pop()
					#alert.setScanFilter(scanfilter)
					#@alerts.push(alert)
				end
			end
		end
	end
end

# === Description
# Object that represents the scan history of a site.
#
class SiteScanHistory
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The Site ID
	attr_reader :site_id
	# //Array containing (ScanSummary*)
	attr_reader :scan_summaries

	def initialize(connection, id)
		@site_id = id
		@error = false
		@connection = connection
		@scan_summaries = Array.new()

		r = @connection.execute('<SiteScanHistoryRequest' + ' session-id="' + @connection.session_id + '" site-id="' + @site_id + '"/>')
		status = r.success
	end
end

# === Description
# Object that represents a listing of devices for a site or the entire NSC. Note that only devices which are accessible to the account used to create the connection object will be returned. This object is created and populated automatically with the instantiation of a new Site object.
#
class SiteDeviceListing

	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The Site ID. 0 if all sites are specified.
	attr_reader :site_id
	# //Array of (Device)*
	attr_reader :devices

	def initialize(connection, site_id = 0)

		@site_id = site_id
		@error = false
		@connection = connection
		@devices = Array.new()

		r = nil
		if (@site_id)
			r = @connection.execute('<SiteDeviceListingRequest session-id="' + connection.session_id + '" site-id="' + @site_id + '"/>')
		else
			r = @connection.execute('<SiteDeviceListingRequest session-id="' + connection.session_id + '"/>')
		end

		if(r.success)
			response.elements.each('SiteDeviceListingResponse/SiteDevices/device') do |d|
				@devices.push(Device.new(d.attributes['id'],@site_id,d.attributes["address"],d.attributes["riskfactor"],d.attributes['riskscore']))
			end
		end
	end
end

# === Description
# Object that represents a site, including the site configuration, scan history, and device listing.
#
# === Example
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc.login()
#
#   # Get an Existing Site
#   site_existing = Site.new(nsc,184)
#
#   # Create a New Site, add some hosts, and save it to the NSC
#   site = Site.new(nsc)
#   site.setSiteConfig("New Site", "New Site Created in the API")
#
#   # Add the hosts
#   site.site_config.addHost(HostName.new("localhost"))
#   site.site_config.addHost(IPRange.new("192.168.7.1","192.168.7.255"))
#   site.site_config.addHost(IPRange.new("10.1.20.30"))
#
#   status = site.saveSite()
#
class Site
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The Site ID
	# site_id = -1 means create a new site. The NSC will assign a new site_id on SiteSave.
	attr_reader :site_id
	# A summary overview of this site
	# SiteSummary Object
	attr_reader :site_summary
	# The configuration of this site
	# SiteConfig Object
	attr_reader :site_config
	# The device listing for this site
	# SiteDeviceListing Object
	attr_reader :site_device_listing
	# The scan history of this site
	# SiteScanHistory Object
	attr_reader :site_scan_history

	def initialize(connection, site_id = -1)
		@error = false
		@connection = connection
		@site_id = site_id

		# If site_id > 0 then get SiteConfig
		if (@site_id.to_i > 0)
			# Create new SiteConfig object
			@site_config = SiteConfig.new()
			# Populate SiteConfig Obect with Data from the NSC
			@site_config.getSiteConfig(@connection,@site_id)
			@site_summary = SiteSummary.new(@site_id, @site_config.site_name, @site_config.description, @site_config.riskfactor)
			@site_scan_history = SiteScanHistory.new(@connection,@site_id)
			@site_device_listing = SiteDeviceListing.new(@connection,@site_id)

		else
			# Just in case user enters a number > -1 or = 0
			@site_id = -1

			@site_config = SiteConfig.new()
			setSiteConfig("New Site " + rand(999999999999).to_s,"")
			@site_summary = nil

		end

	end

	# Creates a new site summary
	def setSiteSummary(site_name, description, riskfactor = 1)
		@site_summary = SiteSummary.new(-1,site_name,description,riskfactor)

	end

	# Creates a new site configuration
	def setSiteConfig(site_name, description, riskfactor = 1)
		setSiteSummary(site_name,description,riskfactor)
		@site_config = SiteConfig.new()
		@site_config._set_site_id(-1)
		@site_config._set_site_name(site_name)
		@site_config._set_description(description)
		@site_config._set_riskfactor(riskfactor)
		@site_config._set_scanConfig(ScanConfig.new(-1,"tmp","full-audit"))
		@site_config._set_connection(@connection)

	end

	# Initiates a scan of this site. If successful returns scan_id and engine_id in an associative array. Returns false if scan is unsuccessful.
	def scanSite()
		r = @connection.execute('<SiteScanRequest session-id="' + "#{@connection.session_id}" + '" site-id="' + "#{@site_id}" + '"/>')
		if(r.success)
			res = {}
			r.res.elements.each('//Scan/') do |s|
				res[:scan_id]   = s.attributes['scan-id']
				res[:engine_id] = s.attributes['engine-id']
			end
			return res
		else
			return false
		end
	end

	# Saves this site in the NSC
	def saveSite()
		r = @connection.execute('<SiteSaveRequest session-id="' + @connection.session_id + '">' + getSiteXML() + ' </SiteSaveRequest>')
		if (r.success)
			@site_id =  r.attributes['site-id']
			@site_config._set_site_id(@site_id)
			@site_config.scanConfig._set_configID(@site_id)
			@site_config.scanConfig._set_name(@site_id)
			return true
		else
			return false
		end
	end

	def deleteSite()
		r = @connection.execute('<SiteDeleteRequest session-id="' + @connection.session_id.to_s + '" site-id="' + @site_id + '"/>')
		r.success
	end


	def printSite()
		puts "Site ID: " + @site_summary.id
		puts "Site Name: " + @site_summary.site_name
		puts "Site Description: " + @site_summary.description
		puts "Site Risk Factor: " + @site_summary.riskfactor
	end

	def getSiteXML()

		xml = '<Site id="' + "#{@site_config.site_id}" + '" name="' + "#{@site_config.site_name}" + '" description="' + "#{@site_config.description}" + '" riskfactor="' + "#{@site_config.riskfactor}" + '">'

		xml += ' <Hosts>'

		@site_config.hosts.each do |h|

			if (h.class.to_s == "Nexpose::IPRange")
				if (h.to and not h.to.empty?)
					xml += ' <range from="' + h.from + '" to="' + h.to + '"/>'
				else
					xml += ' <range from="' + h.from + '"/>'
				end

			elsif (h.class.to_s == "Nexpose::HostName")

				xml += ' <host>' + h.hostname + '</host>'

			end

		end
		xml +=' </Hosts>'

		xml += ' <Credentials>'
		@site_config.credentials.each do |c|
			xml += ' <adminCredentials'
			if (c.service)
				xml += ' service="' + c.service + '"'
			end

			if (c.host)
				xml += ' host="' + c.host + '"'
			end
			xml += '>'

			if (c.isblob)
				xml += c.securityblob
			end

			xml += '</adminCredentials>'

		end
		xml += ' </Credentials>'

		xml += ' <Alerting>'
		@site_config.alerts.each do |a|

			case a.type
			when :smtp
				xml += ' <smtpAlert name="' + a.name + '" enabled="' + a.enabled + '" sender="' + a.sender + '" limitText="' + a.limitText + '">'
				a.recipients.each do |r|
					xml += ' <recipient>' + r + '</recipient>'
				end
				xml += ' <vulnFilter typeMask="' + a.vulnFilter.typeMask + '" maxAlerts="' + a.vulnFilter.maxAlerts + '" severityThreshold="' + a.vulnFilter.severityThreshold + '"/>'
				xml += ' </smtpAlert>'

			when :snmp
				xml += ' <snmpAlert name="' + a.name + '" enabled="' + a.enabled + '" community="' + a.community + '" server="' + a.server + '">'
				xml += ' <vulnFilter typeMask="' + a.vulnFilter.typeMask + '" maxAlerts="' + a.vulnFilter.maxAlerts + '" severityThreshold="' + a.vulnFilter.severityThreshold + '"/>'
				xml += ' </snmpAlert>'

			when :syslog
				xml += ' <syslogAlert name="' + a.name + '" enabled="' + a.enabled + '" server="' + a.server + '">'
				xml += ' <vulnFilter typeMask="' + a.vulnFilter.typeMask + '" maxAlerts="' + a.vulnFilter.maxAlerts + '" severityThreshold="' + a.vulnFilter.severityThreshold + '"/>'
				xml += ' </syslogAlert>'
			end
		end

		xml += ' </Alerting>'

		xml += ' <ScanConfig configID="' + "#{@site_config.scanConfig.configID}" + '" name="' + "#{@site_config.scanConfig.name}" + '" templateID="' + "#{@site_config.scanConfig.templateID}" + '" configVersion="' + "#{@site_config.scanConfig.configVersion}" + '">'

		xml += ' <Schedules>'
		@site_config.scanConfig.schedules.each do |s|
			xml += ' <Schedule enabled="' + s.enabled + '" type="' + s.type + '" interval="' + s.interval + '" start="' + s.start + '"/>'
		end
		xml += ' </Schedules>'

		xml += ' <ScanTriggers>'
		@site_config.scanConfig.scanTriggers.each do |s|

			if (s.class.to_s == "Nexpose::AutoUpdate")
				xml += ' <autoUpdate enabled="' + s.enabled + '" incremental="' + s.incremental + '"/>'
			end
		end

		xml += ' </ScanTriggers>'

		xml += ' </ScanConfig>'

		xml += ' </Site>'

		return xml
	end
end

# === Description
# Object that represents administrative credentials to be used during a scan. When retrived from an existing site configuration the credentials will be returned as a security blob and can only be passed back as is during a Site Save operation. This object can only be used to create a new set of credentials.
#
class AdminCredentials

	# Security blob for an existing set of credentials
	attr_reader :securityblob
	# Designates if this object contains user defined credentials or a security blob
	attr_reader :isblob
	# The service for these credentials. Can be All.
	attr_reader :service
	# The host for these credentials. Can be Any.
	attr_reader :host
	# The port on which to use these credentials.
	attr_reader :port
	# The user id or username
	attr_reader :userid
	# The password
	attr_reader :password
	# The realm for these credentials
	attr_reader :realm


	def initialize(isblob = false)
		@isblob = isblob
	end

	# Sets the credentials information for this object.
	def setCredentials(service, host, port, userid, password, realm)
		@isblob = false
		@securityblob = nil
		@service = service
		@host = host
		@port = port
		@userid = userid
		@password = password
		@realm = realm
	end

	# TODO: add description
	def setService(service)
		@service = service
	end

	def setHost(host)
		@host = host
	end

	# TODO: add description
	def setBlob(securityblob)
		@isblob = true
		@securityblob = securityblob
	end


end

# === Description
# Object that represents an SMTP (Email) Alert.
#
class SmtpAlert
	# A unique name for this alert
	attr_reader :name
	# If this alert is enabled or not
	attr_reader :enabled
	# The email address of the sender
	attr_reader :sender
	# Limit the text for mobile devices
	attr_reader :limitText
	# Array containing Strings of email addresses
	# Array of strings with the email addresses of the intended recipients
	attr_reader :recipients
	# The vulnerability filter to trigger the alert
	attr_reader :vulnFilter
	# The alert type
	attr_reader :type

	def initialize(name, sender, limitText, enabled = 1)
		@type = :smtp
		@name = name
		@sender = sender
		@enabled = enabled
		@limitText = limitText
		@recipients = Array.new()
		# Sets default vuln filter - All Events
		setVulnFilter(VulnFilter.new("50790400",1))
	end

	# Adds a new Recipient to the recipients array
	def addRecipient(recipient)
		@recipients.push(recipient)
	end

	# Sets the Vulnerability Filter for this alert.
	def setVulnFilter(vulnFilter)
		@vulnFilter = vulnFilter
	end

end

# === Description
# Object that represents an SNMP Alert.
#
class SnmpAlert

	# A unique name for this alert
	attr_reader :name
	# If this alert is enabled or not
	attr_reader :enabled
	# The community string
	attr_reader :community
	# The SNMP server to sent this alert
	attr_reader :server
	# The vulnerability filter to trigger the alert
	attr_reader :vulnFilter
	# The alert type
	attr_reader :type

	def initialize(name, community, server, enabled = 1)
		@type = :snmp
		@name = name
		@community = community
		@server = server
		@enabled = enabled
		# Sets default vuln filter - All Events
		setVulnFilter(VulnFilter.new("50790400",1))
	end

	# Sets the Vulnerability Filter for this alert.
	def setVulnFilter(vulnFilter)
		@vulnFilter = vulnFilter
	end

end

# === Description
# Object that represents a Syslog Alert.
#
class SyslogAlert

	# A unique name for this alert
	attr_reader :name
	# If this alert is enabled or not
	attr_reader :enabled
	# The Syslog server to sent this alert
	attr_reader :server
	# The vulnerability filter to trigger the alert
	attr_reader :vulnFilter
	# The alert type
	attr_reader :type

	def initialize(name, server, enabled = 1)
		@type = :syslog
		@name = name
		@server = server
		@enabled = enabled
		# Sets default vuln filter - All Events
		setVulnFilter(VulnFilter.new("50790400",1))

	end

	# Sets the Vulnerability Filter for this alert.
	def setVulnFilter(vulnFilter)
		@vulnFilter = vulnFilter
	end

end

# TODO: review
# <scanFilter scanStop='0' scanFailed='0' scanStart='1'/>
# === Description
#
class ScanFilter

	attr_reader :scanStop
	attr_reader :scanFailed
	attr_reader :scanStart

	def initialize(scanstop, scanFailed, scanStart)

		@scanStop = scanStop
		@scanFailed = scanFailed
		@scanStart = scanStart

	end

end

# TODO: review
# === Description
#
class VulnFilter

	attr_reader :typeMask
	attr_reader :maxAlerts
	attr_reader :severityThreshold

	def initialize(typeMask, severityThreshold, maxAlerts = -1)

		@typeMask = typeMask
		@maxAlerts = maxAlerts
		@severityThreshold = severityThreshold

	end

end

# TODO add engineID
# === Description
# Object that represents the scanning configuration for a Site.
#
class ScanConfig
	# A unique ID for this scan configuration
	attr_reader :configID
	# The name of the scan template
	attr_reader :name
	# The ID of the scan template used full-audit, exhaustive-audit, web-audit, dos-audit, internet-audit, network-audit
	attr_reader :templateID
	# The configuration version (default is 2)
	attr_reader :configVersion
	# Array of (Schedule)*
	attr_reader :schedules
	# Array of (ScanTrigger)*
	attr_reader :scanTriggers

	def initialize(configID, name, templateID, configVersion = 2)

		@configID = configID
		@name = name
		@templateID = templateID
		@configVersion = configVersion
		@schedules = Array.new()
		@scanTriggers = Array.new()

	end

	# Adds a new Schedule for this ScanConfig
	def addSchedule(schedule)
		@schedules.push(schedule)
	end

	# Adds a new ScanTrigger to the scanTriggers array
	def addScanTrigger(scanTrigger)
		@scanTriggers.push(scanTrigger)
	end

	def _set_configID(configID)
		@configID = configID
	end

	def _set_name(name)
		@name = name
	end

end

# === Description
# Object that holds a scan schedule
#
class Schedule
	# Type of Schedule (daily|hourly|monthly|weekly)
	attr_reader :type
	# The schedule interval
	attr_reader :interval
	# The date and time to start the first scan
	attr_reader :start
	# Enable or disable this schedule
	attr_reader :enabled
	# The date and time to disable to schedule. If null then the schedule will run forever.
	attr_reader :notValidAfter
	# Scan on the same date each time
	attr_reader :byDate

	def initialize(type, interval, start, enabled = 1)

		@type = type
		@interval = interval
		@start = start
		@enabled = enabled

	end



end

# === Description
# Object that holds an event that triggers the start of a scan.
#
class ScanTrigger
	# Type of Trigger (AutoUpdate)
	attr_reader :type
	# Enable or disable this scan trigger
	attr_reader :enabled
	# Sets the trigger to start an incremental scan or a full scan
	attr_reader :incremental

	def initialize(type, incremental, enabled = 1)

		@type = type
		@incremental = incremental
		@enabled = enabled

	end

end

# === Description
# Object that represents a single device in an NSC.
#
class Device

	# A unique device ID (assigned by the NSC)
	attr_reader :id
	# The site ID of this devices site
	attr_reader :site_id
	# IP Address or Hostname of this device
	attr_reader :address
	# User assigned risk multiplier
	attr_reader :riskfactor
	# NeXpose risk score
	attr_reader :riskscore

	def initialize(id, site_id, address, riskfactor=1, riskscore=0)
		@id = id
		@site_id = site_id
		@address = address
		@riskfactor = riskfactor
		@riskscore = riskscore

	end

end


# === Description
# Object that represents a summary of a scan.
#
class ScanSummary
	# The Scan ID of the Scan
	attr_reader :scan_id
	# The Engine ID used to perform the scan
	attr_reader :engine_id
	# TODO: add description
	attr_reader :name
	# The scan start time
	attr_reader :startTime
	# The scan finish time
	attr_reader :endTime
	# The scan status (running|finished|stopped|error| dispatched|paused|aborted|uknown)
	attr_reader :status
	# The number of pending tasks
	attr_reader :tasks_pending
	# The number of active tasks
	attr_reader :tasks_active
	# The number of completed tasks
	attr_reader :tasks_completed
	# The number of "live" nodes
	attr_reader :nodes_live
	# The number of "dead" nodes
	attr_reader :nodes_dead
	# The number of filtered nodes
	attr_reader :nodes_filtered
	# The number of unresolved nodes
	attr_reader :nodes_unresolved
	# The number of "other" nodes
	attr_reader :nodes_other
	# Confirmed vulnerabilities found (indexed by severity)
	# Associative array, indexed by severity
	attr_reader :vuln_exploit
	# Unconfirmed vulnerabilities found (indexed by severity)
	# Associative array, indexed by severity
	attr_reader :vuln_version
	# Not vulnerable checks run (confirmed)
	attr_reader :not_vuln_exploit
	# Not vulnerable checks run (unconfirmed)
	attr_reader :not_vuln_version
	# Vulnerability check errors
	attr_reader :vuln_error
	# Vulnerability checks disabled
	attr_reader :vuln_disabled
	# Vulnerability checks other
	attr_reader :vuln_other

	# Constructor
	# ScanSummary(can_id, $engine_id, $name, tartTime, $endTime, tatus)
	def initialize(scan_id, engine_id, name, startTime, endTime, status)

		@scan_id = scan_id
		@engine_id = engine_id
		@name = name
		@startTime = startTime
		@endTime = endTime
		@status = status

	end

end

# TODO
# === Description
# Object that represents the overview statistics for a particular scan.
#
# === Examples
#
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc.login()
#
#   # Get a Site (Site ID = 12) from the NSC
#   site = new Site(nsc,12)
#
#   # Start a Scan of this site and pause for 1 minute
#   scan1 = site.scanSite()
#   sleep(60)
#
#   # Get the Scan Statistics for this scan
#   scanStatistics = new ScanStatistics(nsc,scan1["scan_id"])
#
#   # Print out number of confirmed vulnerabilities with a 10 severity
#   puts scanStatistics.scansummary.vuln_exploit[10]
#
#   # Print out the number of pending tasks left in the scan
#   puts scanStatistics.scan_summary.tasks_pending
#
class ScanStatistics
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :reseponse_xml
	# The Scan ID
	attr_reader :scan_id
	# The ScanSummary of the scan
	attr_reader :scan_summary
	# The NSC Connection associated with this object
	attr_reader :connection

	# Vulnerability checks other
	attr_reader :vuln_other
	def initialize(connection, scan_id)
		@error = false
		@connection = connection
		@scan_id = scan_id
	end
end

# ==== Description
# Object that represents a listing of all of the scan engines available on to an NSC.
#
class EngineListing
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# Array containing (EngineSummary*)
	attr_reader :engines
	# The number of scan engines
	attr_reader :engine_count

	# Constructor
	# EngineListing (connection)
	def initialize(connection)
		@connection = connection
	end
end

# ==== Description
# Object that represents the summary of a scan engine.
#
# ==== Examples
#
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc.login()
#
#   # Get the engine listing for the connection
#   enginelisting = EngineListing.new(nsc)
#
#   # Print out the status of the first scan engine
#   puts enginelisting.engines[0].status
#
class EngineSummary
	# A unique ID that identifies this scan engine
	attr_reader :id
	# The name of this scan engine
	attr_reader :name
	# The hostname or IP address of the engine
	attr_reader :address
	# The port there the engine is listening
	attr_reader :port
	# The engine status (active|pending-auth| incompatible|not-responding|unknown)
	attr_reader :status

	# Constructor
	# EngineSummary(id, name, address, port, status)
	def initialize(id, name, address, port, status)
		@id = id
		@name = name
		@address = address
		@port = port
		@status = status
	end

end


# TODO
class EngineActivity
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The Engine ID
	attr_reader :engine_id
	# Array containing (ScanSummary*)
	attr_reader :scan_summaries


end

# === Description
# Object that represents a listing of all of the vulnerabilities in the vulnerability database
#
class VulnerabilityListing

	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# Array containing (VulnerabilitySummary*)
	attr_reader :vulnerability_summaries
	# The number of vulnerability definitions
	attr_reader :vulnerability_count

	# Constructor
	# VulnerabilityListing(connection)
	def initialize(connection)
		@error = false
		@vulnerability_summaries = []
		@connection = connection

		r = @connection.execute('<VulnerabilityListingRequest session-id="' + @connection.session_id + '"/>')

		if (r.success)
			response.elements.each('VulnerabilityListingResponse/VulnerabilitySummary') do |v|
				@vulnerability_summaries.push(VulnerabilitySummary.new(v.attributes['id'],v.attributes["title"],v.attributes["severity"]))
			end
		else
			@error = true
			@error_msg = 'VulnerabilitySummaryRequest Parse Error'
		end
		@vulnerability_count = @vulnerability_summaries.length
	end
end

# === Description
# Object that represents the summary of an entry in the vulnerability database
#
class VulnerabilitySummary

	# The unique ID string for this vulnerability
	attr_reader :id
	# The title of this vulnerability
	attr_reader :title
	# The severity of this vulnerability (1 – 10)
	attr_reader :severity

	# Constructor
	# VulnerabilitySummary(id, title, severity)
	def initialize(id, title, severity)
		@id = id
		@title = title
		@severity = severity

	end

end

# === Description
#
class Reference

	attr_reader :source
	attr_reader :reference

	def initialize(source, reference)
		@source = source
		@reference = reference
	end
end

# === Description
# Object that represents the details for an entry in the vulnerability database
#
class VulnerabilityDetail
	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The unique ID string for this vulnerability
	attr_reader :id
	# The title of this vulnerability
	attr_reader :title
	# The severity of this vulnerability (1 – 10)
	attr_reader :severity
	# The pciSeverity of this vulnerability
	attr_reader :pciSeverity
	# The CVSS score of this vulnerability
	attr_reader :cvssScore
	# The CVSS vector of this vulnerability
	attr_reader :cvssVector
	# The date this vulnerability was published
	attr_reader :published
	# The date this vulnerability was added to NeXpose
	attr_reader :added
	# The last date this vulnerability was modified
	attr_reader :modified
	# The HTML Description of this vulnerability
	attr_reader :description
	# External References for this vulnerability
	# Array containing (Reference)
	attr_reader :references
	# The HTML Solution for this vulnerability
	attr_reader :solution

	# Constructor
	# VulnerabilityListing(connection,id)
	def initialize(connection, id)

		@error = false
		@connection = connection
		@id = id
		@references = []

		r = @connection.execute('<VulnerabilityDetailsRequest session-id="' + @connection.session_id + '" vuln-id="' + @id + '"/>')

		if (r.success)
			r.res.elements.each('VulnerabilityDetailsResponse/Vulnerability') do |v|
				@id = v.attributes['id']
				@title = v.attributes["title"]
				@severity = v.attributes["severity"]
				@pciSeverity = v.attributes['pciSeverity']
				@cvssScore = v.attributes['cvssScore']
				@cvssVector = v.attributes['cvssVector']
				@published = v.attributes['published']
				@added = v.attributes['added']
				@modified = v.attributes['modified']

				v.elements.each('description') do |d|
					@description = d.to_s.gsub(/\<\/?description\>/i, '')
				end

				v.elements.each('solution') do |s|
					@solution = s.to_s.gsub(/\<\/?solution\>/i, '')
				end

				v.elements.each('references/reference') do |r|
					@references.push(Reference.new(r.attributes['source'],r.text))
				end
			end
		else
			@error = true
			@error_msg = 'VulnerabilitySummaryRequest Parse Error'
		end

	end
end

# === Description
# Object that represents the summary of a Report Configuration.
#
class ReportConfigSummary
	# The Report Configuration ID
	attr_reader :id
	# A unique name for the Report
	attr_reader :name
	# The report format
	attr_reader :format
	# The date of the last report generation
	attr_reader :last_generated_on
	# Relative URI of the last generated report
	attr_reader :last_generated_uri

	# Constructor
	# ReportConfigSummary(id, name, format, last_generated_on, last_generated_uri)
	def initialize(id, name, format, last_generated_on, last_generated_uri)

		@id = id
		@name = name
		@format = format
		@last_generated_on = last_generated_on
		@last_generated_uri = last_generated_uri

	end

end

# === Description
# Object that represents the schedule on which to automatically generate new reports.
class ReportHistory

	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The report definition (report config) ID
	# Report definition ID
	attr_reader :config_id
	# Array (ReportSummary*)
	attr_reader :report_summaries


	def initialize(connection, config_id)

		@error = false
		@connection = connection
		@config_id = config_id
		@report_summaries = []

		reportHistory_request = APIRequest.new('<ReportHistoryRequest session-id="' + "#{connection.session_id}" + '" reportcfg-id="' + "#{@config_id}" + '"/>',@connection.geturl())
		reportHistory_request.execute()
		@response_xml = reportHistory_request.response_xml
		@request_xml = reportHistory_request.request_xml

	end

	def xml_parse(response)
		response = REXML::Document.new(response.to_s)
		status =  response.root.attributes['success']
		if (status == '1')
			response.elements.each('ReportHistoryResponse/ReportSummary') do |r|
				@report_summaries.push(ReportSummary.new(r.attributes["id"], r.attributes["cfg-id"], r.attributes["status"], r.attributes["generated-on"],r.attributes['report-uri']))
			end
		else
			@error = true
			@error_msg = 'Error ReportHistoryReponse'
		end
	end

end

# === Description
# Object that represents the summary of a single report.
class ReportSummary

	# The Report ID
	attr_reader :id
	# The Report Configuration ID
	attr_reader :cfg_id
	# The status of this report
	# available | generating | failed
	attr_reader :status
	# The date on which this report was generated
	attr_reader :generated_on
	# The relative URI of the report
	attr_reader :report_uri

	def initialize(id, cfg_id, status, generated_on, report_uri)

		@id = id
		@cfg_id = cfg_id
		@status = status
		@generated_on = generated_on
		@report_uri = report_uri

	end

end

# === Description
#
class ReportAdHoc

	attr_reader :error
	attr_reader :error_msg
	attr_reader :connection
	# Report Template ID strong e.g. full-audit
	attr_reader :template_id
	# pdf|html|xml|text|csv|raw-xml
	attr_reader :format
	# Array of (ReportFilter)*
	attr_reader :filters
	attr_reader :request_xml
	attr_reader :response_xml
	attr_reader :report_decoded


	def initialize(connection, template_id = 'full-audit', format = 'raw-xml')

		@error = false
		@connection = connection
		@xml_tag_stack = array()
		@filters = Array.new()
		@template_id = template_id
		@format = format

	end

	def addFilter(filter_type, id)

		# filter_type can be site|group|device|scan
		# id is the ID number. For scan, you can use 'last' for the most recently run scan
		filter = new ReportFilter.new(filter_type,id)
		filters.push(filter)

	end

	def generate()
		request_xml = '<ReportAdhocGenerateRequest session-id="' + @connection.session_id + '">'
		request_xml += '<AdhocReportConfig template-id="' + @template_id + '" format="' + @format + '">'
		request_xml += '<Filters>'
		@filters.each do |f|
			request_xml += '<filter type="' + f.type + '" id="'+  f.id + '"/>'
		end
		request_xml += '</Filters>'
		request_xml += '</AdhocReportConfig>'
		request_xml += '</ReportAdhocGenerateRequest>'

		myReportAdHoc_request = APIRequest.new(request_xml, @connection.geturl())
		myReportAdHoc_request.execute()

		myReportAdHoc_response = myReportAdHoc_request.response_xml
	end

end

# === Description
# Object that represents the configuration of a report definition.
#
class ReportConfig

	# true if an error condition exists; false otherwise
	attr_reader :error
	# Error message string
	attr_reader :error_msg
	# The last XML request sent by this object
	attr_reader :request_xml
	# The last XML response received by this object
	attr_reader :response_xml
	# The NSC Connection associated with this object
	attr_reader :connection
	# The ID for this report definition
	attr_reader :config_id
	# A unique name for this report definition
	attr_reader :name
	# The template ID used for this report definition
	attr_reader :template_id
	# html, db, txt, xml, raw-xml, csv, pdf
	attr_reader :format
	# XXX new
	attr_reader :timezone
	# XXX new
	attr_reader :owner
	# Array of (ReportFilter)* - The Sites, Asset Groups, or Devices to run the report against
	attr_reader :filters
	# Automatically generate a new report at the conclusion of a scan
	# 1 or 0
	attr_reader :generate_after_scan
	# Schedule to generate reports
	# ReportSchedule Object
	attr_reader :schedule
	# Store the reports on the server
	# 1 or 0
	attr_reader :storeOnServer
	# Location to store the report on the server
	attr_reader :store_location
	# Form to send the report via email
	# "file", "zip", "url", or NULL (don’t send email)
	attr_reader :email_As
	# Send the Email to all Authorized Users
	# boolean - Send the Email to all Authorized Users
	attr_reader :email_to_all
	# Array containing the email addresses of the recipients
	attr_reader :email_recipients
	# IP Address or Hostname of SMTP Relay Server
	attr_reader :smtp_relay_server
	# Sets the FROM field of the Email
	attr_reader :sender
	# TODO
	attr_reader :db_export
	# TODO
	attr_reader :csv_export
	# TODO
	attr_reader :xml_export


	def initialize(connection, config_id = -1)

		@error = false
		@connection = connection
		@config_id = config_id
		@xml_tag_stack = Array.new()
		@filters = Array.new()
		@email_recipients = Array.new()
		@name = "New Report " + rand(999999999).to_s

		r = @connection.execute('<ReportConfigRequest session-id="' + @connection.session_id.to_s + '" reportcfg-id="' + @config_id.to_s + '"/>')
		if (r.success)
			r.res.elements.each('ReportConfigResponse/ReportConfig') do |r|
				@name = r.attributes['name']
				@format = r.attributes['format']
				@timezone = r.attributes['timezone']
				@id = r.attributes['id']
				@template_id = r.attributes['template-id']
				@owner = r.attributes['owner']
			end
		else
			@error = true
			@error_msg = 'Error ReportHistoryReponse'
		end
	end

	# === Description
	# Generate a new report on this report definition. Returns the new report ID.
	def generateReport(debug = false)
		return generateReport(@connection, @config_id, debug)
	end
	# === Description
	# Save the report definition to the NSC.
	# Returns the config-id.
	def saveReport()
		r = @connection.execute('<ReportSaveRequest session-id="' + @connection.session_id.to_s + '">' + getXML().to_s + ' </ReportSaveRequest>')
		if(r.success)
			@config_id = r.attributes['reportcfg-id']
			return true
		end
		return false
	end

	# === Description
	# Adds a new filter to the report config
	def addFilter(filter_type, id)
		filter = ReportFilter.new(filter_type,id)
		@filters.push(filter)
	end

	# === Description
	# Adds a new email recipient
	def addEmailRecipient(recipient)
		@email_recipients.push(recipient)
	end

	# === Description
	# Sets the schedule for this report config
	def setSchedule(schedule)
		@schedule = schedule
	end

	def getXML()

		xml = '<ReportConfig id="' + @config_id.to_s + '" name="' + @name.to_s + '" template-id="' + @template_id.to_s + '" format="' + @format.to_s + '">'

		xml += ' <Filters>'

		@filters.each do |f|
			xml += ' <' + f.type.to_s + ' id="' + f.id.to_s + '"/>'
		end

		xml += ' </Filters>'

		xml += ' <Generate after-scan="' + @generate_after_scan.to_s + '">'

		if (@schedule)
			xml += ' <Schedule type="' + @schedule.type.to_s + '" interval="' + @schedule.interval.to_s + '" start="' + @schedule.start.to_s + '"/>'
		end

		xml += ' </Generate>'

		xml += ' <Delivery>'

		xml += ' <Storage storeOnServer="' + @storeOnServer.to_s + '">'

		if (@store_location and @store_location.length > 0)
			xml += ' <location>' + @store_location.to_s + '</location>'
		end

		xml += ' </Storage>'


		xml += ' </Delivery>'

		xml += ' </ReportConfig>'

		return xml
	end

	def set_name(name)
		@name = name
	end

	def set_template_id(template_id)
		@template_id = template_id
	end

	def set_format(format)
		@format = format
	end

	def set_email_As(email_As)
		@email_As = email_As
	end

	def set_storeOnServer(storeOnServer)
		@storeOnServer = storeOnServer
	end

	def set_smtp_relay_server(smtp_relay_server)
		@smtp_relay_server = smtp_relay_server
	end

	def set_sender(sender)
		@sender = sender
	end

	def set_generate_after_scan(generate_after_scan)
		@generate_after_scan = generate_after_scan
	end
end

# === Description
# Object that represents a report filter which determines which sites, asset
# groups, and/or devices that a report is run against.  gtypes are
# "SiteFilter", "AssetGroupFilter", "DeviceFilter", or "ScanFilter".  gid is
# the site-id, assetgroup-id, or devce-id.  ScanFilter, if used, specifies
# a specifies a specific scan to use as the data source for the report. The gid
# can be a specific scan-id or "first" for the first run scan, or “last” for
# the last run scan.
#
class ReportFilter

	attr_reader :type
	attr_reader :id

	def initialize(type, id)

		@type = type
		@id = id

	end

end

# === Description
# Object that represents the schedule on which to automatically generate new reports.
#
class ReportSchedule

	# The type of schedule
	# (daily, hourly, monthly, weekly)
	attr_reader :type
	# The frequency with which to run the scan
	attr_reader :interval
	# The earliest date to generate the report
	attr_reader :start

	def initialize(type, interval, start)

		@type = type
		@interval = interval
		@start = start

	end


end

class ReportTemplateListing

	attr_reader :error_msg
	attr_reader :error
	attr_reader :request_xml
	attr_reader :response_xml
	attr_reader :connection
	attr_reader :xml_tag_stack
	attr_reader :report_template_summaries#;  //Array (ReportTemplateSummary*)


	def ReportTemplateListing(connection)

		@error = nil
		@connection = connection
		@report_template_summaries = Array.new()

		r = @connection.execute('<ReportTemplateListingRequest session-id="' + connection.session_id.to_s + '"/>')
		if (r.success)
			r.res.elements.each('ReportTemplateListingResponse/ReportTemplateSummary') do |r|
				@report_template_summaries.push(ReportTemplateSumary.new(r.attributes['id'],r.attributes['name']))
			end
		else
			@error = true
			@error_msg = 'ReportTemplateListingRequest Parse Error'
		end

	end

end


class ReportTemplateSummary

	attr_reader :id
	attr_reader :name
	attr_reader :description

	def ReportTemplateSummary(id, name, description)

		@id = id
		@name = name
		@description = description

	end

end


class ReportSection

	attr_reader :name
	attr_reader :properties

	def ReportSection(name)

		@properties = Array.new()
		@name = name
	end


	def addProperty(name, value)

		@properties[name.to_s] = value
	end

end


# TODO add
def self.site_device_scan(connection, site_id, device_array, host_array, debug = false)

	request_xml = '<SiteDevicesScanRequest session-id="' + connection.session_id.to_s + '" site-id="' + site_id.to_s + '">'
	request_xml += '<Devices>'
	device_array.each do |d|
		request_xml += '<device id="' + d.to_s + '"/>'
	end
	request_xml += '</Devices>'
	request_xml += '<Hosts>'
	# The host array can only by single IP addresses for now. TODO: Expand to full API Spec.
	host_array.each do |h|
		request_xml += '<range from="' + h.to_s + '"/>'
	end
	request_xml += '</Hosts>'
	request_xml += '</SiteDevicesScanRequest>'

	r = connection.execute(request_xml)
	r.success ? { :engine_id => r.attributes['engine_id'], :scan_id => r.attributes['scan-id'] } : nil
end

# === Description
# TODO
def self.getAttribute(attribute, xml)
	value = ''
	#@value = substr(substr(strstr(strstr(@xml,@attribute),'"'),1),0,strpos(substr(strstr(strstr(@xml,@attribute),'"'),1),'"'))
	return value
end

# === Description
# Returns an ISO 8601 formatted date/time stamp. All dates in NeXpose must use this format.
def self.get_iso_8601_date(int_date)
#@date_mod = date('Ymd\THis000', @int_date)
	date_mod = ''
return date_mod
end

# ==== Description
# Echos the last XML API request and response for the specified object.  (Useful for debugging)
def self.printXML(object)
	puts "request" + object.request_xml.to_s
	puts "response is " + object.response_xml.to_s
end



def self.testa(ip, port, user, passwd)
	nsc = Connection.new(ip, user, passwd, port)

	nsc.login
	site_listing = SiteListing.new(nsc)

	site_listing.sites.each do |site|
		puts "name is #{site.site_name}"
		puts "id is #{site.id}"
	end

=begin
	## Site Delete ##
	nsc.login
	status = deleteSite(nsc, '244', true)
	puts "status: #{status}"
=end
=begin
	nsc.login

	site = Site.new(nsc)
	site.setSiteConfig("New Site 3", "New Site Description")
	site.site_config.addHost(IPRange.new("10.1.90.86"))
	status = site.saveSite()
	report_config = ReportConfig.new(nsc)
	report_config.set_template_id("raw-xml")
	report_config.set_format("xml")
	report_config.addFilter("SiteFilter",site.site_id)
	report_config.set_generate_after_scan(1)
	report_config.set_storeOnServer(1)
	report_config.saveReport()
	puts report_config.config_id.to_s

	site.scanSite()

	nsc.logout
=end

=begin
	nsc.login
	site = Site.new(nsc)
	site.setSiteConfig("New Site 3", "New Site Description")
	site.site_config.addHost(IPRange.new("10.1.90.86"))
	status = site.saveSite()

	report_config = ReportConfig.new(nsc)
	report_config.set_template_id("audit-report")
	report_config.set_format("pdf")
	report_config.addFilter("SiteFilter",site.site_id)
	report_config.set_email_As("file")
	report_config.set_smtp_relay_server("")
	report_config.set_sender("nexpose@rapid7.com")
	report_config.addEmailRecipient("jabra@rapid7.com")
	report_config.set_generate_after_scan(1)
	report_config.saveReport()

	site.scanSite()
=end

	nsc.logout

=begin
	vuln_listing = VulnerabilityListing.new(nsc)
	vuln_listing.vulnerability_summaries.each do |v|
		puts "vuln id #{v.id}"
		exit
	end
	n.logout
=end


=begin
	nsc.login
	vuln_id = 'generic-icmp-timestamp'
	vuln = VulnerabilityDetail.new(n,vuln_id.to_s)
	puts "#{vuln.id}"
	puts "#{vuln.title}"
	puts "#{vuln.pciSeverity}"
	puts "#{vuln.cvssScore}"
	puts "#{vuln.cvssVector}"
	puts "#{vuln.description}"
	vuln.references.each do |r|
		puts "source: #{r.source}"
		puts "reference: #{r.reference}"
	end
	puts "#{vuln.solution}"
=end

=begin
	site = Site.new(n)
	site.setSiteConfig("New Site Name", "New Site Description")
	site.site_config.addHost(IPRange.new("10.1.90.86"))
	#site.site_config.addHost(HostName.new("localhost"))
	#site.site_config.addHost(IPRange.new("192.168.7.1","192.168.7.20"))
	#site.site_config.addHost(IPRange.new("10.1.90.130"))
	status = site.saveSite()

	puts "#{site.site_id}"
	site.scanSite
	nsc.logout
=end

=begin
	site = Site.new(nsc,'263')

	site.printSite()
	site.getSiteXML()
	puts "#{site.site_id}"
	puts "#{site.site_config.description}"
	puts "#{site.site_config.riskfactor}"
	nsc.logout
=end

	#site.scanSite()
=begin
	site_config = SiteConfig.new()


	my_site = site_config.getSiteConfig(n, '244')

	history = SiteScanHistory.new(n, '244')

	devices = SiteDeviceListing.new(n, '244')
=end

=begin
	site_listing = SiteListing.new(n)

	site_listing.sites.each do |site|
		puts "name is #{site.site_name}"
	end
=end

end

=begin
def self.test(url,user,pass)
	xml = "<?xml version='1.0' encoding='UTF-8'?>
		<!DOCTYPE LoginRequest [
		<!ELEMENT LoginRequest EMPTY>
		<!ATTLIST LoginRequest sync-id CDATA '0'>
		<!ATTLIST LoginRequest user-id CDATA 'user'>
		<!ATTLIST LoginRequest password CDATA 'pass'>
		]>
		<LoginRequest sync-id='0' password='#{pass}' user-id='#{user}'/>"

	r = APIRequest.new(xml, url)
	r.execute
	puts r.response_xml
end

# Run the program
# Logon, get a session-id, list the sites, then logout.
test("http://x.x.x.x:3780", 'nxadmin', 'PASSWORD')
=end

end

