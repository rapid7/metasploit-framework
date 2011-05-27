require File.join(File.expand_path(File.dirname(__FILE__)),"nokogiri_doc_mixin")

module Rex
	module Parser

		# If Nokogiri is available, define Nexpose document class. 
		load_nokogiri && class NexposeSimpleDocument < Nokogiri::XML::SAX::Document

		include NokogiriDocMixin

		attr_reader :text

		# Triggered every time a new element is encountered. We keep state
		# ourselves with the @state variable, turning things on when we
		# get here (and turning things off when we exit in end_element()).
		def start_element(name=nil,attrs=[])
			attrs = normalize_attrs(attrs)
			block = @block
			@state[:current_tag][name] = true
			case name
			when "device"
				record_device(attrs)
			when "service"
				record_service(attrs)
			when "fingerprint"
				record_service_fingerprint(attrs)
				record_host_fingerprint(attrs)
			when "description"
				@state[:has_text] = true
				record_service_fingerprint_description(attrs)
				record_host_fingerprint_data(name,attrs)
			when "vendor", "family", "product", "version", "architecture"
				@state[:has_text] = true
				record_host_fingerprint_data(name,attrs)
			when "vulnerability"
				record_service_vuln(attrs)
				record_host_vuln(attrs)
			when "id"
				@state[:has_text] = true
				record_service_vuln_id(attrs)
				record_host_vuln_id(attrs)
			end
		end

		# This breaks xml-encoded characters, so need to append
		def characters(text)
			return unless @state[:has_text]
			@text ||= ""
			@text << text
		end

		# When we exit a tag, this is triggered.
		def end_element(name=nil)
			block = @block
			@state[:current_tag].delete name
			case name
			when "device" # Wrap it up
				collect_device_data
				host_object = report_host &block
				report_services(host_object)
				report_host_fingerprint(host_object)
				report_vulns(host_object)
				# Reset the state once we close a host
				@state.delete_if {|k| k != :current_tag}
				@report_data = {:wspace => @args[:wspace]}
			when "fingerprint"
				@state[:in_fingerprint] = false
			when "description"
				@state[:has_text] = false
				collect_service_fingerprint_description
				collect_host_fingerprint_data(name)
				@text = nil
			when "vendor", "family", "product", "version", "architecture"
				@state[:has_text] = false
				collect_host_fingerprint_data(name)
				@text = nil
			when "service"
				collect_service_data
			when "id"
				@state[:has_text] = false
				collect_service_vuln_id
				collect_host_vuln_id
				@text = nil
			when "vulnerability"
				collect_service_vuln
				collect_host_vuln
				@state[:references] = nil
				@state[:in_vuln] = false
			end
		end

		def report_vulns(host_object)
			vuln_count = 0
			block = @block
			return unless host_object.kind_of? Msf::DBManager::Host
			return unless @report_data[:vulns]
			@report_data[:vulns].each do |vuln|
				if vuln[:refs]
					vuln[:refs] << vuln[:name]
				else
					vuln[:refs] = [vuln[:name]]
				end
				vuln[:refs].uniq!
				data = {
					:workspace => host_object.workspace,
					:host => host_object,
					:name => vuln[:name],
					:info => vuln[:info],
					:refs => vuln[:refs]
				}
				if vuln[:port] && vuln[:proto]
					data[:port] = vuln[:port] 
					data[:proto] = vuln[:proto]
				end
				db.report_vuln(data)
			end
			
		end

		def collect_host_vuln_id
			return unless @state[:in_device]
			return unless @state[:in_vuln]
			return if @state[:in_service]
			return unless @state[:host_vuln_id]
			@state[:references] ||= []
			ref = normalize_ref( @state[:host_vuln_id]["type"], @text )
			@state[:references] << ref if ref
			@state[:host_vuln_id] = nil
			@text = nil
		end

		def collect_service_vuln_id
			return unless @state[:in_device]
			return unless @state[:in_vuln]
			return unless @state[:in_service]
			return unless @state[:service_vuln_id]
			@state[:references] ||= []
			ref = normalize_ref( @state[:service_vuln_id]["type"], @text )
			@state[:references] << ref if ref
			@state[:service_vuln_id] = nil
			@text = nil
		end

		def collect_service_vuln
			return unless @state[:in_device]
			return unless @state[:in_vuln]
			return unless @state[:in_service]
			@report_data[:vulns] ||= []
			return unless actually_vulnerable(@state[:service_vuln])
			return if @state[:service]["port"].to_i == 0
			vid = @state[:service_vuln]["id"].to_s.downcase
			vuln = {
				:name => "NEXPOSE-#{vid}",
				:info => vid,
				:refs => @state[:references],
				:port => @state[:service]["port"].to_i,
				:proto => @state[:service]["protocol"]
			}
			@report_data[:vulns] << vuln
		end

		def collect_host_vuln
			return unless @state[:in_vuln]
			return unless @state[:in_device]
			return if @state[:in_service]
			@report_data[:vulns] ||= []
			return unless actually_vulnerable(@state[:host_vuln])
			vid = @state[:host_vuln]["id"].to_s.downcase
			vuln = {
				:name => "NEXPOSE-#{vid}",
				:info => vid,
				:refs => @state[:references]
			}
			@report_data[:vulns] << vuln
		end

		def record_host_vuln_id(attrs)
			return unless @state[:in_device]
			return if @state[:in_service]
			@state[:host_vuln_id] = attr_hash(attrs)
		end

		def record_host_vuln(attrs)
			return unless @state[:in_device]
			return if @state[:in_service]
			@state[:in_vuln] = true
			@state[:host_vuln] = attr_hash(attrs)
		end

		def record_service_vuln_id(attrs)
			return unless @state[:in_device]
			return unless @state[:in_service]
			@state[:service_vuln_id] = attr_hash(attrs)
		end

		def record_service_vuln(attrs)
			return unless @state[:in_device]
			return unless @state[:in_service]
			@state[:in_vuln] = true
			@state[:service_vuln] = attr_hash(attrs)
		end

		def actually_vulnerable(vuln)
			vuln_result = vuln["resultCode"]
			vuln_result =~ /^V[VE]$/
		end

		def record_device(attrs)
			@state[:in_device] = true
			attrs.each do |k,v|
				next unless k == "address"
				@state[:address] = v
			end
		end

		def record_host_fingerprint(attrs)
			return unless @state[:in_device]
			return if @state[:in_service]
			@state[:in_fingerprint] = true
			@state[:host_fingerprint] = attr_hash(attrs)
		end

		def collect_device_data
			return unless @state[:in_device]
			@report_data[:host] = @state[:address]
			@report_data[:state] = Msf::HostState::Alive # always
		end

		def record_host_fingerprint_data(name, attrs)
			return unless @state[:in_device]
			return if @state[:in_service]
			return unless @state[:in_fingerprint]
			@state[:host_fingerprint] ||= {}
			@state[:host_fingerprint].merge! attr_hash(attrs)
		end

		def collect_host_fingerprint_data(name)
			return unless @state[:in_device]
			return if @state[:in_service]
			return unless @state[:in_fingerprint]
			return unless @text
			@report_data[:host_fingerprint] ||= {}
			@report_data[:host_fingerprint].merge!(@state[:host_fingerprint])
			@report_data[:host_fingerprint][name] = @text.to_s.strip
			@text = nil
		end

		def report_host(&block)
			if host_is_okay
				db.emit(:address,@report_data[:host],&block) if block
				host_object = db.report_host( @report_data.merge(
					:workspace => @args[:wspace] ) )
				if host_object
					db.report_import_note(host_object.workspace, host_object)
				end
				host_object
			end
		end

		def report_host_fingerprint(host_object)
			return unless host_object.kind_of? ::Msf::DBManager::Host
			return unless @report_data[:host_fingerprint].kind_of? Hash
			@report_data[:host_fingerprint].reject! {|k,v| v.nil? || v.empty?}
			return if @report_data[:host_fingerprint].empty?
			note = {
				:workspace => host_object.workspace,
				:host => host_object,
				:type => "host.os.nexpose_fingerprint"
			}
			data = {
				:desc => @report_data[:host_fingerprint]["description"],
				:vendor => @report_data[:host_fingerprint]["vendor"],
				:family => @report_data[:host_fingerprint]["family"],
				:product => @report_data[:host_fingerprint]["product"],
				:version => @report_data[:host_fingerprint]["version"],
				:arch => @report_data[:host_fingerprint]["architecture"]
			}
			db.report_note(note.merge(:data => data))
		end

		def record_service(attrs)
			return unless @state[:in_device]
			@state[:in_service] = true
			@state[:service] = attr_hash(attrs)
		end

		def record_service_fingerprint(attrs)
			return unless @state[:in_device]
			return unless @state[:in_service]
			@state[:in_fingerprint] = true
			@state[:service][:fingerprint] = attr_hash(attrs)
		end

		def record_service_fingerprint_description(attrs)
			return unless @state[:in_device]
			return unless @state[:in_service]
			return unless @state[:in_fingerprint]
		end

		def collect_service_data
			return unless @state[:in_device]
			port_hash = {}
			@report_data[:ports] ||= []
			@state[:service].each do |k,v|
				case k
				when "protocol"
					port_hash[:protocol] = v
				when "port"
					port_hash[:port] = v
				when "name"
					port_hash[:name] = v.to_s.downcase.split("(")[0].strip
					port_hash.delete(:name) if port_hash[:name] == "<unknown>"
				end
			end
			if @state[:service_fingerprint]
				port_hash[:info] = "#{@state[:service_fingerprint]}"
			end
			@report_data[:ports] << port_hash
			@state[:in_service] = false
		end

		def collect_service_fingerprint_description
			return unless @state[:in_device]
			return unless @state[:in_service]
			return unless @state[:in_fingerprint]
			return unless @text
			@state[:service_fingerprint] = @text.to_s.strip
			@text = nil
		end

		def report_services(host_object)
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

