require File.join(File.expand_path(File.dirname(__FILE__)),"nokogiri_doc_mixin")

module Rex
	module Parser

		# If Nokogiri is available, define Template document class. 
		load_nokogiri && class NexposeRawDocument < Nokogiri::XML::SAX::Document

		include NokogiriDocMixin

		attr_reader :tests

		# Triggered every time a new element is encountered. We keep state
		# ourselves with the @state variable, turning things on when we
		# get here (and turning things off when we exit in end_element()).
		def start_element(name=nil,attrs=[])
			attrs = normalize_attrs(attrs)
			block = @block
			@state[:current_tag][name] = true
			case name
			when "nodes" # There are two main sections, nodes and VulnerabilityDefinitions
				@tests = []
			when "node"
				record_host(attrs)
			when "name"
				@state[:has_text] = true
			when "endpoint"
				record_service(attrs)
			when "service"
				record_service_info(attrs)
			when "fingerprint"
				record_service_fingerprint(attrs)
			when "os"
				record_os_fingerprint(attrs)
			when "test" # All the vulns tested for
				record_host_test(attrs)
				record_service_test(attrs)
			when "vulnerability"
				record_vuln(attrs)
			when "reference"
				@state[:has_text] = true
				record_reference(attrs)
			end
		end

		# When we exit a tag, this is triggered.
		def end_element(name=nil)
			block = @block
			case name
			when "node" # Wrap it up
				collect_host_data
				host_object = report_host &block
				report_services(host_object)
				report_fingerprint(host_object)
				# Reset the state once we close a host
				@state.delete_if {|k| k.to_s !~ /^(current_tag|in_nodes)$/}
				@report_data = {:wspace => @args[:wspace]}
			when "name"
				collect_hostname
				@state[:has_text] = false
			when "endpoint"
				collect_service_data
			when "os"
				collect_os_fingerprints
			when "test"
				save_test
			when "vulnerability"
				collect_vuln_info
				report_vuln(&block)
				@state.delete_if {|k| k.to_s !~ /^(current_tag|in_vulndefs)$/}
			when "reference"
				@state[:has_text] = false
				collect_reference
				@text = nil
			end
			@state[:current_tag].delete name
		end

		def collect_reference
			return unless in_tag("references")
			return unless in_tag("vulnerability")
			return unless @state[:vuln]
			@state[:ref][:value] = @text.to_s.strip
			@report_data[:refs] ||= []
			@report_data[:refs] << @state[:ref]
			@state[:ref] = nil
		end

		def collect_vuln_info
			return unless in_tag("VulnerabilityDefinitions")
			return unless in_tag("vulnerability")
			return unless @state[:vuln]
			vuln = @state[:vuln]
			vuln[:refs] = @report_data[:refs]
			@report_data[:vuln] = vuln
			@state[:vuln] = nil
			@report_data[:refs] = nil
		end

		def report_vuln(&block)
			return unless in_tag("VulnerabilityDefinitions")
			return unless @report_data[:vuln]
			return unless @report_data[:vuln][:matches].kind_of? Array
			refs = normalize_references(@report_data[:vuln][:refs])
			refs << "NEXPOSE-#{report_data[:vuln]["id"]}"
			vuln_instances = @report_data[:vuln][:matches].size
			db.emit(:vuln, [refs.last,vuln_instances], &block) if block
			data = {
				:workspace => @args[:wspace],
				:name => refs.last,
				:info => @report_data[:vuln]["title"],
				:refs => refs.uniq
			}
			hosts_keys = {}
			@report_data[:vuln][:matches].each do |match|
				host_data = data.dup
				host_data[:host] = match[:host]
				host_data[:port] = match[:port] if match[:port]
				host_data[:proto] = match[:protocol] if match[:protocol]
				db_report(:vuln, host_data)
				if match[:key]
					hosts_keys[host_data[:host]] ||= []
					hosts_keys[host_data[:host]] << match[:key]
				end
			end
			report_key_note(hosts_keys,data)
			@report_data[:vuln] = nil
		end

		def report_key_note(hosts_keys,data)
			return if hosts_keys.empty?
			hosts_keys.each do |key_host,key_values|
				key_note = {
					:workspace => @args[:wspace],
					:host => key_host,
					:type => "host.vuln.nexpose_keys",
					:data => {},
					:update => :unique_data
				}
				key_values.each do |key_value|
					key_note[:data][data[:name]] ||= []
					next if key_note[:data][data[:name]].include? key_value
					key_note[:data][data[:name]] << key_value
				end
				db_report(:note, key_note)
			end
		end

		def record_reference(attrs)
			return unless in_tag("VulnerabilityDefinitions")
			return unless in_tag("vulnerability")
			@state[:ref] = attr_hash(attrs)
		end

		def record_vuln(attrs)
			return unless in_tag("VulnerabilityDefinitions")
			vuln = attr_hash(attrs)
			matching_tests = @tests.select {|x| x[:id] == vuln["id"].downcase}
			return if matching_tests.empty?
			@state[:vuln] = vuln
			@state[:vuln][:matches] = matching_tests
		end

		def save_test
			return unless in_tag("nodes")
			return unless in_tag("node")
			return unless @state[:test]
			test = { :id => @state[:test][:id]}
			test[:host] = @state[:address]
			test[:port] = @state[:test][:port] if @state[:test][:port]
			test[:protocol] = @state[:test][:protocol] if @state[:test][:protocol]
			test[:key] = @state[:test][:key] if @state[:test][:key]
			@tests << test
			@state[:test] = nil
		end

		def record_os_fingerprint(attrs)
			return unless in_tag("nodes")
			return unless in_tag("fingerprints")
			return unless in_tag("node")
			return if in_tag("service")
			@state[:os] = attr_hash(attrs)
		end

		# Just keep the highest scoring, which is usually the most vague. :(
		def collect_os_fingerprints
			@report_data[:os] ||= {}
			return unless @state[:os]["certainty"].to_f > 0
			return if @report_data[:os]["os_certainty"].to_f > @state[:os]["certainty"].to_f
			@report_data[:os] = {} # Zero it out if we're replacing it.
			@report_data[:os]["os_certainty"] = @state[:os]["certainty"]
			@report_data[:os]["os_vendor"] = @state[:os]["vendor"]
			@report_data[:os]["os_family"] = @state[:os]["family"]
			@report_data[:os]["os_product"] = @state[:os]["product"]
			@report_data[:os]["os_version"] = @state[:os]["version"]
			@report_data[:os]["os_arch"] = @state[:os]["arch"]
		end

		# Just taking the first one.
		def collect_hostname
			if in_tag("node")
				@state[:hostname] ||= @text.to_s.strip if @text
				@text = nil
			end
		end

		def record_service_fingerprint(attrs)
			return unless in_tag("nodes")
			return unless in_tag("node")
			return unless in_tag("service")
			return unless in_tag("fingerprint")
			@state[:service_fingerprint] = attr_hash(attrs)
		end

		def record_service_info(attrs)
			return unless in_tag("nodes")
			return unless in_tag("node")
			return unless in_tag("service")
			@state[:service].merge! attr_hash(attrs)
		end

		def report_fingerprint(host_object)
			return unless host_object.kind_of? ::Msf::DBManager::Host
			return unless @report_data[:os].kind_of? Hash
			note = {
				:workspace => host_object.workspace,
				:host => host_object,
				:type => "host.os.nexpose_fingerprint",
				:data => {
					:family => @report_data[:os]["os_family"],
					:certainty => @report_data[:os]["os_certainty"]
				}
			}
			note[:data][:vendor] = @report_data[:os]["os_vendor"] if @report_data[:os]["os_vendor"]
			note[:data][:product] = @report_data[:os]["os_product"] if @report_data[:os]["os_prduct"]
			note[:data][:version] = @report_data[:os]["os_version"] if @report_data[:os]["os_version"]
			note[:data][:arch] = @report_data[:os]["os_arch"] if @report_data[:os]["os_arch"]
			db_report(:note, note)
		end

		def report_services(host_object)
			return unless host_object.kind_of? ::Msf::DBManager::Host
			return unless @report_data[:ports]
			return if @report_data[:ports].empty?
			reported = []
			@report_data[:ports].each do |svc|
				reported << db_report(:service, svc.merge(:host => host_object))
			end
			reported
		end

		def record_service(attrs)
			return unless in_tag("nodes")
			return unless in_tag("node")
			return unless in_tag("endpoint")
			@state[:service] = attr_hash(attrs)
		end

		def collect_service_data
			return unless in_tag("node")
			return unless in_tag("endpoint")
			port_hash = {}
			@report_data[:ports] ||= []
			@state[:service].each do |k,v|
				case k
				when "protocol"
					port_hash[:proto] = v
				when "port"
					port_hash[:port] = v
				when "status"
					port_hash[:status] = (v == "open" ? Msf::ServiceState::Open : Msf::ServiceState::Closed)
				end
			end
			if @state[:service]
				if state[:service]["name"] == "<unknown>"
					sname = nil
				else
					sname = db.nmap_msf_service_map(@state[:service]["name"])
				end
				port_hash[:name] = sname
			end
			if @state[:service_fingerprint]
				info = []
				info << @state[:service_fingerprint]["product"] if @state[:service_fingerprint]["product"]
				info << @state[:service_fingerprint]["version"] if @state[:service_fingerprint]["version"]
				port_hash[:info] = info.join(" ") if info[0]
			end
			@report_data[:ports] << port_hash.clone
			@state.delete :service_fingerprint
			@state.delete :service
			@report_data[:ports]
		end

		def actually_vulnerable(test)
			return false unless test.has_key? "status"
			return false unless test.has_key? "id"
			['vulnerable-exploited', 'vulnerable-version', 'potential'].include? test["status"]
		end

		def record_host_test(attrs)
			return unless in_tag("nodes")
			return unless in_tag("node")
			return if in_tag("service")
			return unless in_tag("tests")
			test = attr_hash(attrs)
			return unless actually_vulnerable(test)
			@state[:test] = {:id => test["id"].downcase}
			@state[:test][:key] = test["key"] if test["key"]
		end

		def record_service_test(attrs)
			return unless in_tag("nodes")
			return unless in_tag("node")
			return unless in_tag("service")
			return unless in_tag("tests")
			test = attr_hash(attrs)
			return unless actually_vulnerable(test)
			@state[:test] = {
				:id => test["id"].downcase,
				:port => @state[:service]["port"],
				:protocol => @state[:service]["protocol"],
			}
			@state[:test][:key] = test["key"] if test["key"]
		end

		def record_host(attrs)
			return unless in_tag("nodes")
			host_attrs = attr_hash(attrs)
			if host_attrs["status"] == "alive"
				@state[:host_is_alive] = true
				@state[:address] = host_attrs["address"]
				@state[:mac] = host_attrs["hardware-address"] if host_attrs["hardware-address"]
			end
		end

		def collect_host_data
			return unless in_tag("node")
			@report_data[:host] = @state[:address]
			@report_data[:state] = Msf::HostState::Alive
			@report_data[:name] = @state[:hostname] if @state[:hostname]
			if @state[:mac]
				if @state[:mac] =~ /[0-9a-fA-f]{12}/
					@report_data[:mac] = @state[:mac].scan(/.{2}/).join(":")
				else
					@report_data[:mac] = @state[:mac]
				end
			end
		end

		def report_host(&block)
			if host_is_okay
				db.emit(:address,@report_data[:host],&block) if block
				host_object = db_report(:host, @report_data.merge(
					:workspace => @args[:wspace] ) )
				if host_object
					db.report_import_note(host_object.workspace, host_object)
				end
				host_object
			end
		end

	end

end
end

