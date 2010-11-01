module Msf

##
#
# This class provides export capabilities
#
##
class DBManager
class Export

	attr_accessor :workspace

	def initialize(workspace)
		self.workspace = workspace
	end

	def myworkspace
		self.workspace
	end	
	
	def myusername
		@username ||= (ENV['LOGNAME'] || ENV['USERNAME'] || ENV['USER'] || "unknown").to_s.strip.gsub(/[^A-Za-z0-9\x20]/,"_")
	end
	
	def to_xml_file(path, &block)

		yield(:status, "start", "report") if block_given?
		extract_target_entries
		report_file = ::File.open(path, "wb")

		report_file.write %Q|<?xml version="1.0" encoding="UTF-8"?>\n|
		report_file.write %Q|<MetasploitV4>\n|
		report_file.write %Q|<generated time="#{Time.now.utc}" user="#{myusername}" project="#{myworkspace.name.gsub(/[^A-Za-z0-9\x20]/,"_")}" product="framework"/>\n|

		yield(:status, "start", "hosts") if block_given?
		report_file.write %Q|<hosts>\n|
		report_file.flush
		extract_host_info(report_file)
		report_file.write %Q|</hosts>\n|

		yield(:status, "start", "events") if block_given?
		report_file.write %Q|<events>\n|
		report_file.flush
		extract_event_info(report_file)
		report_file.write %Q|</events>\n|

		yield(:status, "start", "services") if block_given?
		report_file.write %Q|<services>\n|
		report_file.flush
		extract_service_info(report_file)
		report_file.write %Q|</services>\n|

		yield(:status, "start", "credentials") if block_given?
		report_file.write %Q|<credentials>\n|
		report_file.flush
		extract_credential_info(report_file)
		report_file.write %Q|</credentials>\n|

		yield(:status, "start", "web sites") if block_given?
		report_file.write %Q|<web_sites>\n|
		report_file.flush
		extract_web_site_info(report_file)
		report_file.write %Q|</web_sites>\n|

		yield(:status, "start", "web pages") if block_given?
		report_file.write %Q|<web_pages>\n|
		report_file.flush
		extract_web_page_info(report_file)
		report_file.write %Q|</web_pages>\n|
		
		yield(:status, "start", "web forms") if block_given?
		report_file.write %Q|<web_forms>\n|
		report_file.flush
		extract_web_form_info(report_file)
		report_file.write %Q|</web_forms>\n|	

		yield(:status, "start", "web vulns") if block_given?
		report_file.write %Q|<web_vulns>\n|
		report_file.flush
		extract_web_vuln_info(report_file)
		report_file.write %Q|</web_vulns>\n|
		
		report_file.write %Q|</MetasploitV4>\n|
		report_file.flush
		report_file.close
		
		yield(:status, "complete", "report") if block_given?		
		
		true
	end

	# A convenience function that bundles together host, event, and service extraction.
	def extract_target_entries
		extract_host_entries
		extract_event_entries
		extract_service_entries
		extract_credential_entries
		extract_note_entries
		extract_vuln_entries
		extract_web_entries
	end

	# Extracts all the hosts from a project, storing them in @hosts and @owned_hosts
	def extract_host_entries
		@owned_hosts = []
		@hosts = myworkspace.hosts
		@hosts.each do |host|
			if host.notes.find :first, :conditions => { :ntype => 'pro.system.compromise' }
				@owned_hosts << host
			end
		end
	end

	# Extracts all events from a project, storing them in @events
	def extract_event_entries
		@events = myworkspace.events.find :all, :order => 'created_at ASC'
	end

	# Extracts all services from a project, storing them in @services
	def extract_service_entries
		@services = myworkspace.services
	end

	# Extracts all credentials from a project, storing them in @creds
	def extract_credential_entries
		@creds = []
		myworkspace.each_cred {|cred| @creds << cred}
	end

	# Extracts all notes from a project, storing them in @notes
	def extract_note_entries
		@notes = myworkspace.notes
	end

	# Extracts all vulns from a project, storing them in @vulns
	def extract_vuln_entries
		@vulns = myworkspace.vulns
	end

	# Extract all web entries, storing them in instance variables
	def extract_web_entries
		@web_sites = myworkspace.web_sites
		@web_pages = myworkspace.web_pages		
		@web_forms = myworkspace.web_forms
		@web_vulns = myworkspace.web_vulns
	end

	# Simple marshalling, for now. Can I use ActiveRecord::ConnectionAdapters::Quoting#quote
	# directly? Is it better to just marshal everything and destroy readability? Howabout
	# XML safety?
	def marshalize(obj)
		case obj
		when String
			obj.strip
		when TrueClass, FalseClass, Float, Fixnum, Bignum, Time
			obj.to_s.strip
		when BigDecimal
			obj.to_s("F")
		when NilClass
			"NULL"
		else
			[Marshal.dump(obj)].pack("m").gsub(/\s+/,"")
		end
	end
	
	def create_xml_element(key,value)
		tag = key.gsub("_","-")
		el = REXML::Element.new(tag)
		if value
			data = marshalize(value)
			data.force_encoding(Encoding::BINARY) if data.respond_to?('force_encoding')
			data.gsub!(/([\x00-\x08\x0b\x0c\x0e-\x19\x80-\xFF])/){ |x| "\\x%.2x" % x.unpack("C*")[0] }
			el << REXML::Text.new(data)
		end
		return el
	end

	# ActiveRecord's to_xml is easy and wrong. This isn't, on both counts.
	def extract_host_info(report_file)
		@hosts.each do |h|
			report_file.write("  <host>\n")
			host_id = h.attributes["id"]

			# Host attributes
			h.attributes.each_pair do |k,v|
				el = create_xml_element(k,v)
				report_file.write("    #{el}\n") # Not checking types
			end

			# Service sub-elements
			report_file.write("    <services>\n")
			@services.find_all_by_host_id(host_id).each do |e|
				report_file.write("      <service>\n")
				e.attributes.each_pair do |k,v|
					el = create_xml_element(k,v)
					report_file.write("      #{el}\n")
				end
				report_file.write("      </service>\n")
			end
			report_file.write("    </services>\n")

			# Notes sub-elements
			report_file.write("    <notes>\n")
			@notes.find_all_by_host_id(host_id).each do |e|
				report_file.write("      <note>\n")
				e.attributes.each_pair do |k,v|
					el = create_xml_element(k,v)
					report_file.write("      #{el}\n")
				end
				report_file.write("      </note>\n")
			end
			report_file.write("    </notes>\n")

			# Vulns sub-elements
			report_file.write("    <vulns>\n")
			@vulns.find_all_by_host_id(host_id).each do |e|
				report_file.write("      <vuln>\n")
				e.attributes.each_pair do |k,v|
					el = create_xml_element(k,v)
					report_file.write("      #{el}\n")
				end
				report_file.write("      </vuln>\n")
			end
			report_file.write("    </vulns>\n")

			# Credential sub-elements
			report_file.write("    <creds>\n")
			@creds.each do |cred|
				next unless cred.service.host.id == host_id
				report_file.write("      <cred>\n")
				report_file.write("      #{create_xml_element("port",cred.service.port)}\n")
				report_file.write("      #{create_xml_element("sname",cred.service.name)}\n")
				cred.attributes.each_pair do |k,v|
					next if k.strip =~ /id$/
					el = create_xml_element(k,v)
					report_file.write("      #{el}\n")
				end
				report_file.write("      </cred>\n")
			end
			report_file.write("    </creds>\n")

			report_file.write("  </host>\n")
		end
		report_file.flush		
	end

	# Extract event data from @events
	def extract_event_info(report_file)
		@events.each do |e|
			report_file.write("  <event>\n")
			e.attributes.each_pair do |k,v|
				el = create_xml_element(k,v)
				report_file.write("      #{el}\n")
			end
			report_file.write("  </event>\n")
			report_file.write("\n")
		end
		report_file.flush
	end

	# Extract service data from @services
	def extract_service_info(report_file)
		@services.each do |e|
			report_file.write("  <service>\n")
			e.attributes.each_pair do |k,v|
				el = create_xml_element(k,v)
				report_file.write("      #{el}\n")
			end
			report_file.write("  </service>\n")
			report_file.write("\n")
		end
		report_file.flush
	end
	
	# Extract credential data from @creds
	def extract_credential_info(report_file)
		@creds.each do |c|
			report_file.write("  <credential>\n")
			c.attributes.each_pair do |k,v|
				cr = create_xml_element(k,v)
				report_file.write("      #{cr}\n")
			end
			report_file.write("  </credential>\n")
			report_file.write("\n")
		end
		report_file.flush
	end

	# Extract service data from @services
	def extract_service_info(report_file)
		@services.each do |e|
			report_file.write("  <service>\n")
			e.attributes.each_pair do |k,v|
				el = create_xml_element(k,v)
				report_file.write("      #{el}\n")
			end
			report_file.write("  </service>\n")
			report_file.write("\n")
		end
		report_file.flush
	end

	# Extract web site data from @web_sites
	def extract_web_site_info(report_file)
		@web_sites.each do |e|
			report_file.write("  <web_site>\n")
			e.attributes.each_pair do |k,v|
				el = create_xml_element(k,v)
				report_file.write("      #{el}\n")
			end
			
			site = e
			el = create_xml_element("host", site.service.host.address)
			report_file.write("      #{el}\n")
			
			el = create_xml_element("port", site.service.port)			
			report_file.write("      #{el}\n")

			el = create_xml_element("ssl", site.service.name == "https")			
			report_file.write("      #{el}\n")			
			
			report_file.write("  </web_site>\n")
		end
		report_file.flush
	end
	
	# Extract web pages, forms, and vulns 
	def extract_web_info(report_file, tag, entries)
		entries.each do |e|
			report_file.write("  <#{tag}>\n")
			e.attributes.each_pair do |k,v|
				el = create_xml_element(k,v)
				report_file.write("      #{el}\n")
			end			
			
			site = e.web_site
			el = create_xml_element("vhost", site.vhost)
			report_file.write("      #{el}\n")
						
			el = create_xml_element("host", site.service.host.address)
			report_file.write("      #{el}\n")
			
			el = create_xml_element("port", site.service.port)			
			report_file.write("      #{el}\n")

			el = create_xml_element("ssl", site.service.name == "https")			
			report_file.write("      #{el}\n")	
						
			report_file.write("  </#{tag}>\n")
		end
		report_file.flush
	end
	
	# Extract web pages
	def extract_web_page_info(report_file)
		extract_web_info(report_file, "web_page", @web_pages)
	end
	
	# Extract web forms
	def extract_web_form_info(report_file)
		extract_web_info(report_file, "web_form", @web_forms)
	end
	
	# Extract web vulns
	def extract_web_vuln_info(report_file)
		extract_web_info(report_file, "web_vuln", @web_vulns)
	end			

end
end
end

