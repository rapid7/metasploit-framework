module Rex
	module Parser

		# Determines if Nokogiri is available and if it's a minimum
		# acceptable version.
		def self.load_nokogiri
			@nokogiri_loaded = false
			begin
				require 'nokogiri'
				major,minor = Nokogiri::VERSION.split(".")[0,2]
				if major.to_i >= 1
					if minor.to_i >= 4
						@nokogiri_loaded = true
					end
				end
			rescue LoadError => e
				@nokogiri_loaded = false
				@nokogiri_error  = e
			end
			@nokogiri_loaded
		end

		def self.nokogiri_loaded
			!!@nokogiri_loaded
		end

		# If Nokogiri is available, define Nmap document class. 
		load_nokogiri && class NmapDocument < Nokogiri::XML::SAX::Document

		attr_reader :args, :db, :state, :block, :report_data

		def initialize(args,db,&block)
			@args = args
			@db = db
			@state = {}
			@block = block if block
			@report_data = {:wspace => args[:wspace]}
			super()
		end

		# Turn XML attribute pairs in to more workable hashes (there
		# are better Enumerable tricks in Ruby 1.9, but ignoring for now)
		def attr_hash(attrs)
			h = {}
			attrs.each {|k,v| h[k] = v}
			h
		end

		def valid_ip(addr)
			valid = false
			valid = ::Rex::Socket::RangeWalker.new(addr).valid? rescue false
			!!valid
		end

		# If there's an address, it's not on the blacklist, 
		# it has ports, and the port list isn't
		# empty... it's okay.
		def host_is_okay
			return false unless @report_data[:host]
			return false unless valid_ip(@report_data[:host])
			return false unless @report_data[:state] == Msf::HostState::Alive
			if @args[:blacklist]
				return false if @args[:blacklist].include?(@report_data[:host])
			end
			return false unless @report_data[:ports]
			return false if @report_data[:ports].empty?
			return true
		end

		def determine_port_state(v)
			case v
			when "open"
				Msf::ServiceState::Open
			when "closed"
				Msf::ServiceState::Closed
			when "filtered"
				Msf::ServiceState::Filtered
			when "unknown"
				Msf::ServiceState::Unknown
			end
		end

		# Compare OS fingerprinting data
		def better_os_match(orig_hash,new_hash)
			return false unless new_hash.has_key? "accuracy"
			return true unless orig_hash.has_key? "accuracy"
			new_hash["accuracy"].to_i > orig_hash["accuracy"].to_i
		end

		# Nokogiri 1.4.4 (and presumably beyond) generates attrs as pairs,
		# like [["value1","foo"],["value2","bar"]] (but not hashes for some 
		# reason). 1.4.3.1 (and presumably 1.4.3.x and prior) generates attrs
		# as a flat array of strings. We want array_pairs.
		def normalize_attrs(attrs)
			attr_pairs = []
			case attrs.first
			when Array, NilClass
				attr_pairs = attrs
			when String
				attrs.each_index {|i| 
					next if i % 2 == 0
					attr_pairs << [attrs[i-1],attrs[i]]
				}
			else # Wow, yet another format! It's either from the distant past or distant future.
				raise ::Msf::DBImportError.new("Unknown format for XML attributes. Please check your Nokogiri version.")
			end
			return attr_pairs
		end
		
		# Triggered every time a new element is encountered. We keep state
		# ourselves with the @state variable, turning things on when we
		# get here (and turning things off when we exit in end_element()).
		def start_element(name=nil,attrs=[])
			attrs = normalize_attrs(attrs)
			block = @block
			case name
			when "host"
				@state[:in_host] = true
			when "os"
				if @state[:in_host]
					@state[:in_os] = true
				end
			when "status"
				record_host_status(attrs)
			when "address"
				record_addresses(attrs)
			when "osclass"
				record_host_osclass(attrs)
			when "osmatch"
				record_host_osmatch(attrs)
			when "uptime"
				record_host_uptime(attrs)
			when "hostname"
				record_hostname(attrs,&block)
			when "port"
				record_port(attrs) 
			when "state"
				record_port_state(attrs)
			when "service"
				record_port_service(attrs)
			when "script" # Not actually used in import?
				record_port_script(attrs)
				record_host_script(attrs)
				# Ignoring post scripts completely
			when "trace"
				record_host_trace(attrs)
			when "hop"
				record_host_hop(attrs)
			end
		end

		# We can certainly get fancier with self.send() magic, but
		# leaving this pretty simple for now.

		def record_host_hop(attrs)
			return unless @state[:in_host]
			return unless @state[:in_trace]
			hops = attr_hash(attrs)
			hops["name"] = hops.delete "host"
			@state[:trace][:hops] << hops
		end

		def record_host_trace(attrs)
			return unless @state[:in_host]
			@state[:in_trace] = true
			@state[:trace] = attr_hash(attrs)
			@state[:trace][:hops] = []
		end

		def record_host_uptime(attrs)
			return unless @state[:in_host]
			@state[:uptime] = attr_hash(attrs)
		end

		def record_host_osmatch(attrs)
			return unless @state[:in_host]
			return unless @state[:in_os]
			temp_hash = attr_hash(attrs)
			if temp_hash["accuracy"].to_i == 100
				@state[:os]["osmatch"] = temp_hash["name"]
			end
		end

		def record_host_osclass(attrs)
			return unless @state[:in_host]
			return unless @state[:in_os]
			@state[:os] ||= {}
			temp_hash = attr_hash(attrs)
			if better_os_match(@state[:os],temp_hash)
				@state[:os] = temp_hash
			end
		end

		def record_hostname(attrs)
			return unless @state[:in_host]
			if attr_hash(attrs)["type"] == "PTR"
				@state[:hostname] = attr_hash(attrs)["name"]
			end
		end

		def record_host_script(attrs)
			return unless @state[:in_host]
			return if @state[:in_port]
			temp_hash = attr_hash(attrs)
			@state[:hostscripts] ||= {}
			@state[:hostscripts].merge! temp_hash
			temp_hash[:addresses] = @state[:addresses]
			db.emit(:host_script,temp_hash,&block) if block
		end

		def record_port_script(attrs)
			return unless @state[:in_host]
			return unless @state[:in_port]
			temp_hash = attr_hash(attrs)
			@state[:portscripts] ||= {}
			@state[:portscripts].merge! temp_hash
			temp_hash[:addresses] = @state[:addresses]
			temp_hash[:port] = @state[:port]
			db.emit(:port_script,temp_hash,&block) if block
		end

		def record_port_service(attrs)
			return unless @state[:in_host]
			return unless @state[:in_port]
			svc = attr_hash(attrs)
			if svc["name"] && @args[:fix_services]
				svc["name"] = db.nmap_msf_service_map(svc["name"])
			end
			@state[:port] = @state[:port].merge(svc)
		end

		def record_port_state(attrs)
			return unless @state[:in_host]
			return unless @state[:in_port]
			temp_hash = attr_hash(attrs)
			@state[:port] = @state[:port].merge(temp_hash)
		end

		def record_port(attrs)
			return unless @state[:in_host]
			@state[:in_port] = true
			@state[:port] ||= {}
			svc = attr_hash(attrs)
			@state[:port] = @state[:port].merge(svc)
		end

		def record_host_status(attrs)
			return unless @state[:in_host]
			attrs.each do |k,v|
				next unless k == "state"
				@state[:host_alive] = (v == "up") 
			end
		end

		def record_addresses(attrs)
			return unless @state[:in_host]
			@state[:addresses] ||= {}
			address = nil
			type = nil
			attrs.each do |k,v|
				if k == "addr"
					address = v
				elsif k == "addrtype"
					type = v
				end
			end
			@state[:addresses][type] = address
		end

		# When we exit a tag, this is triggered.
		def end_element(name=nil)
			block = @block
			case name
			when "os"
				collect_os_data
				@state[:in_os] = false
				@state[:os] = {}
			when "port"
				collect_port_data 
				@state[:in_port] = false
				@state[:port] = {}
			when "script"
				if @state[:in_host]
					if @state[:in_port]
						@state[:portscripts] = {}
					else
						@state[:hostscripts] = {}
					end
				end
			when "trace"
				@state[:in_trace] = false
			when "host" # Roll everything up now
				collect_host_data
				host_object = report_host &block
				if host_object
					db.report_import_note(@args[:wspace],host_object)
					report_services(host_object,&block)
					report_fingerprint(host_object)
					report_uptime(host_object)
					report_traceroute(host_object)
				end
				@state = {}
			end
		end

		def collect_os_data
			return unless @state[:in_host]
			if @state[:os]
				@report_data[:os_fingerprint] = {
					:type => "host.os.nmap_fingerprint",
					:data => {
						:os_vendor => @state[:os]["vendor"],
						:os_family => @state[:os]["osfamily"],
						:os_version => @state[:os]["osgen"],
						:os_accuracy => @state[:os]["accuracy"].to_i
					}
				}
				if @state[:os].has_key? "osmatch"
					@report_data[:os_fingerprint][:data][:os_match] = @state[:os]["osmatch"]
				end
			end
		end

		def collect_host_data
			if @state[:host_alive] 
				@report_data[:state] = Msf::HostState::Alive
			else
				@report_data[:state] = Msf::HostState::Dead
			end
			if @state[:addresses] 
				if @state[:addresses].has_key? "ipv4"
					@report_data[:host] = @state[:addresses]["ipv4"]
				elsif @state[:addresses].has_key? "ipv6"
					@report_data[:host] = @state[:addresses]["ipv6"]
				end
			end
			if @state[:addresses] and @state[:addresses].has_key?("mac")
				@report_data[:mac] = @state[:addresses]["mac"]
			end
			if @state[:hostname]
				@report_data[:name] = @state[:hostname]
			end
			if @state[:uptime]
				@report_data[:last_boot] = @state[:uptime]["lastboot"]
			end
			if @state[:trace] and @state[:trace].has_key?(:hops)
				@report_data[:traceroute] = @state[:trace]
			end
		end

		def collect_port_data(&block)
			return unless @state[:in_host]
			if @args[:fix_services]
				if @state[:port]["state"] == "filtered"
					return
				end
			end
			@report_data[:ports] ||= []
			port_hash = {}
			extra = []
			@state[:port].each do |k,v|
				case k
				when "protocol"
					port_hash[:protocol] = v
				when "portid"
					port_hash[:port] = v
				when "state"
					port_hash[:state] = determine_port_state(v)
				when "name"
					port_hash[:name] = v
				when "reason"
					port_hash[:reason] = v
				when "product"
					extra[0] = v
				when "version"
					extra[1] = v
				when "extrainfo"
					extra[2] = v
				end
			end
			port_hash[:info] = extra.compact.join(" ") unless extra.empty?
			# Skip localhost port results when they're unknown
			if( port_hash[:reason] == "localhost-response" &&
				  port_hash[:state] == Msf::ServiceState::Unknown )
				@report_data[:ports]
			else
				@report_data[:ports] << port_hash
			end
		end

		def report_traceroute(host_object)
			return unless host_object.kind_of? ::Msf::DBManager::Host
			return unless @report_data[:traceroute]
			db.report_note(
				:workspace => host_object.workspace,
				:host => host_object,
				:type => "host.nmap.traceroute",
				:data => {
					'port' => @report_data[:traceroute]["port"].to_i,
					'proto' => @report_data[:traceroute]["proto"].to_s,
					'hops' => @report_data[:traceroute][:hops]
				}
			)
		end

		def report_uptime(host_object)
			return unless host_object.kind_of? ::Msf::DBManager::Host
			return unless @report_data[:last_boot]
			db.report_note(
				:workspace => host_object.workspace,
				:host => host_object,
				:type => "host.last_boot",
				:data => { :time => @report_data[:last_boot] }
			)
		end

		def report_fingerprint(host_object)
			return unless host_object.kind_of? ::Msf::DBManager::Host
			return unless @report_data[:os_fingerprint]
			db.report_note(
				@report_data[:os_fingerprint].merge(
					:workspace => host_object.workspace,
					:host => host_object
				)
			)
		end

		def report_host(&block)
			if host_is_okay
				host_object = db.report_host( @report_data.merge(
					:workspace => @args[:wspace] ) )
				db.emit(:address,@report_data[:host],&block) if block
				host_object
			end
		end

		def report_services(host_object,&block)
			return unless host_object.kind_of? ::Msf::DBManager::Host
			return unless @report_data[:ports]
			return if @report_data[:ports].empty?
			reported = []
			@report_data[:ports].each do |svc|
				reported << db.report_service(svc.merge(:host => host_object))
			end
			reported
		end

	end

end
end

