require "rex/parser/nokogiri_doc_mixin"
require "date"

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
				@tests = {}
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
				@state[:has_text] = true
				record_host_test(attrs)
				record_service_test(attrs)
			when "vulnerability"
				record_vuln(attrs)
			when "reference"
				@state[:has_text] = true
				record_reference(attrs)
			when "description"
				@state[:has_text] = true	
			when "solution"
				@state[:has_text] = true
			when "tag"
				@state[:has_text] = true
			when "tags"
				@state[:tags] = []
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
				@text = nil
			when "endpoint"
				collect_service_data
				@state.delete(:cached_service_object)
			when "os"
				collect_os_fingerprints
			when "test"
				report_test(&block)
				@state[:has_text] = false
				@text = nil
			when "vulnerability"
				collect_vuln_info
				report_vuln(&block)
				@state.delete_if {|k| k.to_s !~ /^(current_tag|in_vulndefs)$/}
			when "reference"
				@state[:has_text] = false
				collect_reference
				@text = nil
			when "description"
				@state[:has_text] = false
				collect_vuln_description
				@text = nil
			when "solution"
				@state[:has_text] = false
				collect_vuln_solution
				@text = nil	
			when "tag"
				@state[:has_text] = false
				collect_tag
				@text = nil
			when "tags"
				@state.delete(:tags)
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

		def collect_vuln_description
			return unless in_tag("description")
			return unless in_tag("vulnerability")
			return unless @state[:vuln]
			@report_data[:vuln_description] = @text.to_s.strip
		end

		def collect_vuln_solution
			return unless in_tag("solution")
			return unless in_tag("vulnerability")
			return unless @state[:vuln]
			@report_data[:vuln_solution] = @text.to_s.strip
		end

		def collect_tag
			return unless in_tag("tag")
			return unless in_tag("tags")
			return unless in_tag("vulnerability")
			return unless @state[:vuln]
			@report_data[:vuln_tags] ||= []
			@report_data[:vuln_tags] << @text.to_s.strip
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

			::ActiveRecord::Base.connection_pool.with_connection {

			refs = normalize_references(@report_data[:vuln][:refs])
			refs << "NEXPOSE-#{report_data[:vuln]["id"]}"
			vuln_instances = @report_data[:vuln][:matches].size
			db.emit(:vuln, [refs.last,vuln_instances], &block) if block

			vuln_ids = @report_data[:vuln][:matches].map{ |v| v[0] }
			vdet_ids = @report_data[:vuln][:matches].map{ |v| v[1] }

			refs = refs.uniq.map{|x| db.find_or_create_ref(:name => x) }

			# Assign title and references to all vuln_ids
			# Mass update fails due to the join table || ::Mdm::Vuln.where(:id => vuln_ids).update_all({ :name => @report_data[:vuln]["title"], :refs => refs } )
			vuln_ids.each do |vid|
				vuln = ::Mdm::Vuln.find(vid)
				next unless vuln
				vuln.name = @report_data[:vuln]["title"]
				vuln.refs = refs
				if vuln.changed?
					vuln.save!
				end
			end

			# Mass update vulnerability details across the database based on conditions
			vdet_info = { :title => @report_data[:vuln]["title"] }
			vdet_info[:description]     = @report_data[:vuln_description]      unless @report_data[:vuln_description].to_s.empty?
			vdet_info[:solution]        = @report_data[:vuln_solution]         unless @report_data[:vuln_solution].to_s.empty? 
			vdet_info[:nx_tags]         = @report_data[:vuln_tags].join(", ")      if ( @report_data[:vuln_tags].kind_of?(::Array) and @report_data[:vuln_tags].length > 0 )
			vdet_info[:nx_severity]     = @report_data[:vuln]["severity"].to_f     if @report_data[:vuln]["severity"]
			vdet_info[:nx_pci_severity] = @report_data[:vuln]["pciSeverity"].to_f  if @report_data[:vuln]["pciSeverity"]
			vdet_info[:cvss_score]      = @report_data[:vuln]["cvssScore"].to_f    if @report_data[:vuln]["cvssScore"]
			vdet_info[:cvss_vector]     = @report_data[:vuln]["cvssVector"]        if @report_data[:vuln]["cvssVector"]
			
			%W{ published added modified }.each do |tf|
				next if not @report_data[:vuln][tf]
				ts = DateTime.parse(@report_data[:vuln][tf]) rescue nil
				next if not ts
				vdet_info[ "nx_#{tf}".to_sym ] = ts
			end
			
			::Mdm::VulnDetail.where(:id => vdet_ids).update_all(vdet_info)

			@report_data[:vuln] = nil

			}
		end

		def record_reference(attrs)
			return unless in_tag("VulnerabilityDefinitions")
			return unless in_tag("vulnerability")
			@state[:ref] = attr_hash(attrs)
		end

		def record_vuln(attrs)
			return unless in_tag("VulnerabilityDefinitions")
			vuln = attr_hash(attrs)
			matching_tests = @tests[ vuln["id"].downcase ]
			return unless matching_tests
			return if matching_tests.empty?
			@state[:vuln] = vuln
			@state[:vuln][:matches] = matching_tests
		end

		# XML Export 2.0 includes additional test keys:
		# <test id="unix-unowned-files-or-dirs" status="vulnerable-exploited" scan-id="6381" vulnerable-since="20120322T124352665" pci-compliance-status="pass">

		def report_test
			return unless in_tag("nodes")
			return unless in_tag("node")
			return unless @state[:test]

			vuln_info = {
				:workspace => @args[:wspace],
				# This name will be overwritten during the vuln definition
				# parsing via mass-update.
				:name => "NEXPOSE-" + @state[:test][:id].downcase,
				:host => @state[:cached_host_object] || @state[:address]
			}

			if @state[:cached_service_object]
				vuln_info[:service] = @state[:cached_service_object]
			else
				vuln_info[:port] = @state[:test][:port] if @state[:test][:port]
				vuln_info[:protocol] = @state[:test][:protocol] if @state[:test][:protocol]
			end

			# This hash feeds a vuln_details row for this vulnerability
			vdet = { :src => 'nexpose', :nx_vuln_id => @state[:test][:id] }

			# This hash defines the matching criteria to overwrite an existing entry
			vkey = { :src => 'nexpose', :nx_vuln_id => @state[:test][:id] }

			if @state[:device_id]	
				vdet[:nx_device_id] = @state[:device_id]
				vkey[:nx_device_id] = @state[:device_id]
			end

			if @state[:test][:key]
				vdet[:nx_proof_key] = @state[:test][:key]
				vkey[:nx_proof_key] = @state[:test][:key]
			end

			vdet[:nx_console_id]  = @console_id if @console_id
			vdet[:nx_vuln_status] = @state[:test][:status] if @state[:test][:status]
			
			proof = @text.to_s.strip
			vuln_info[:info] = proof
			vdet[:proof]     = proof 

			# Configure the find key for vuln_details
			vdet[:key] = vkey

			::ActiveRecord::Base.connection_pool.with_connection {

			# Report the vulnerability
			vuln = db.report_vuln(vuln_info)
			
			if vuln
				# Report the vulnerability details
				detail = db.report_vuln_details(vuln, vdet)

				# Cache returned host and service objects if necessary
				@state[:cached_host_object] ||= vuln.host
				@state[:cached_service_object] ||= vuln.service if vuln.service

				# Record the ID of this vuln for a future mass update that
				# brings in title, risk, description, solution, etc
				@tests[ @state[:test][:id].downcase ] ||= []
				@tests[ @state[:test][:id].downcase ] << [ vuln.id, detail.id ]
			end

			}
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
			return unless host_object.kind_of? ::Mdm::Host
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
			return unless host_object.kind_of? ::Mdm::Host
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
			@state[:test][:status] = test["status"] if test["status"]
		end

		def record_host(attrs)
			return unless in_tag("nodes")
			host_attrs = attr_hash(attrs)
			if host_attrs["status"] == "alive"
				@state[:host_is_alive] = true
				@state[:address] = host_attrs["address"]
				@state[:mac] = host_attrs["hardware-address"] if host_attrs["hardware-address"]
				@state[:device_id] = host_attrs["device-id"] if host_attrs["device-id"]
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

			@report_data[:device_id] = @state[:device_id] if @state[:device_id]
		end

		def report_host(&block)
			if host_is_okay
				db.emit(:address,@report_data[:host],&block) if block
				device_id   = @report_data.delete(:device_id)
				host_object = db_report(:host, @report_data.merge(:workspace => @args[:wspace] ) )
				if host_object
					db.report_import_note(host_object.workspace, host_object)
					if device_id
						detail = { 
							:key => { :src => 'nexpose' }, 
							:src => 'nexpose',
							:nx_device_id => device_id 
						}
						detail[:nx_console_id] = @nx_console_id if @nx_console_id 
						db.report_host_details(host_object, detail)
					end
				end
				host_object
			end
		end

	end

end
end

