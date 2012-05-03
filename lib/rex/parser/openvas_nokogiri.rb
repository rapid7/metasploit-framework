require "rex/parser/nokogiri_doc_mixin"

module Rex
	module Parser

		# If Nokogiri is available, define OpenVAS document class. 
		load_nokogiri && class OpenVASDocument < Nokogiri::XML::SAX::Document

		include NokogiriDocMixin
		
		# ourselves with the @state variable, turning things on when we
		# get here (and turning things off when we exit in end_element()).
		def start_element(name=nil,attrs=[])
			attrs = normalize_attrs(attrs)
			block = @block
			@state[:current_tag][name] = true
			case name
			when "get_reports_response"
			when "report"
			when "report_format"
			when "sort"
			when "field"
			when "order"
			when "filters"
			when "phrase"
			when "notes"
			when "overrides"
			when "apply_overrides"
			when "result_hosts_only"
			when "min_cvss_base_score"
			when "filter"
			when "scan_run_status"
			when "task"
			when "name"
			when "scan_start"
			when "ports"
			when "port"
			when "host"
			when "threat"
			when "result_count"
			when "full"
			when "filtered"
			when "debug"
			when "hole"
			when "info"
			when "log"
			when "warning"
			when "false_positive"
			when "results"
			when "result"
			when "subnet"
			when "host"
			when "port"
			when "nvt"
			when "cvss_base"
			when "risk_factor"
			when "cve"
			when "bid"
			when "description"
			end
		end

		# When we exit a tag, this is triggered.
		def end_element(name=nil)
			block = @block
			case name
			when "description"
			when "bid"
			when "cve"
			when "risk_factor"
			when "cvss_base"
			when "nvt"
			when "port"
			when "host"
			when "subnet"
			when "result"
			when "results"
			when "false_positive"
			when "warning"
			when "log"
			when "info"
			when "hole"
			when "debug"
			when "filtered"
			when "full"
			when "result_count"
			when "threat"
			when "host"
			when "port"
			when "ports"
			when "scan_start"
			when "task"
			when "name"
			when "scan_run_status"
			when "filter"
			when "min_cvss_base"
			when "results_hosts_only"
			when "apply_overrides"
			when "overrides"
			when "notes"
			when "phrase"
			when "sort"
			when "order"
			when "field"
			when "report_format"
			when "report"
			when "get_reports_response"
			end
			@state[:current_tag].delete name
		end
	end
end
end

