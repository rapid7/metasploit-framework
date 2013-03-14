# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
module Parser

	# If Nokogiri is available, define  document class.
	load_nokogiri && class FusionVMDocument < Nokogiri::XML::SAX::Document


	include NokogiriDocMixin

	def start_element(name=nil,attrs=[])
		return nil if in_tag("JobOrder")
		attrs = normalize_attrs(attrs)
		attrs = attr_hash(attrs)
		@state[:current_tag][name] = true
		case name
		when "IPAddress"
			thost={}
			return nil unless attrs["IPAddress"] and attrs["HostName"]
			thost = {
				:host      => attrs["IPAddress"],
				:name      => attrs["HostName"],
				:workspace => @args[:wspace]
			}
			thost[:host] = attrs["IPAddress"]
			thost[:name] = attrs["HostName"]
			@host = db_report(:host, thost)
		when "OS"
			@state[:has_text] = true
		when "Port"
			@service = {
				:host   => @host,
				:port   => attrs["Number"],
				:state  => "open"
			}
		when "Service"
			@state[:has_text] = true
		when "Protocol"
			@state[:has_text] = true
		when "Exposure"
			@vuln = {
				:host => @host,
				:refs => []
			}
		when "Title"
			@state[:has_text] = true
		when "Description"
			@state[:has_text] = true
		when "CVE"
			@state[:has_text] = true
		when "References"
			@state[:has_text] = true
		end
	end

	def end_element(name=nil)
		unless in_tag("JobOrder")
			case name
			when "OS"
				unless @host.nil? or @text.blank?
					tnote = {
						:type       => "host.os.fusionvm_fingerprint",
						:data       => { :os => @text.strip },
						:host       => @host,
						:workspace  => @args[:wspace]
					}
					db_report(:note, tnote)
					@host.normalize_os
				end
			when  "IPAdress"
				@host = nil
			when "Service"
				@service[:name] = @text.strip
			when "Protocol"
				@service[:proto] = @text.strip.downcase
			when "Port"
				db_report(:service, @service)
			when "Exposure"
				db_report(:vuln, @vuln)
			when "Title"
				@vuln[:name] = @text.strip
			when "Description"
				@vuln[:info] = @text.strip
			when "CVE"
				@vuln[:refs] << "CVE-#{@text.strip}"
			when "References"
				unless @text.blank?
					@text.split(' ').each do |ref|
						next unless ref.start_with? "http"
						if ref =~ /MS\d{2}-\d{3}/
							@vuln[:refs] << "MSB-#{$&}"
						else
							@vuln[:refs] << "URL-#{ref.strip}"
						end
					end
				end
			end
		end
		@text = nil
		@state[:current_tag].delete name
	end



end
end
end
