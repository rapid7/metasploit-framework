# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
	module Parser

	load_nokogiri && class WapitiDocument < Nokogiri::XML::SAX::Document

		include NokogiriDocMixin

		def start_element(name=nil,attrs=[])
			attrs = normalize_attrs(attrs)
			block = @block
			@state[:current_tag][name] = true

			case name
			when "timestamp"
				@state[:has_text] = true
			when "url"
				@state[:has_text] = true
			when "addr"
				@state[:has_text] = true
			when "port"
				@state[:has_text] = true
			when "parameter"
				@state[:has_text] = true
			when "info"
				@state[:has_text] = true
			when "description"
				@state[:has_text] = true
			when "solution"
				@state[:has_text] = true
			when "title"
				@state[:has_text] = true
			end
		end

		def end_element(name=nil)
			block = @block
			case name
			when "timestamp"
				@state[:timestamp] = @text.strip
				@text = nil
			when "url"
				@state[:url] = @text.strip
				@text = nil
			when "addr"
				@state[:host] = @text.strip
				@text = nil
			when "port"
				@state[:port] = @text.strip
				@text = nil
			when "parameter"
				@state[:parameter] = @text.strip
				@text = nil
			when "info"
				@state[:info] = @text.strip
				@text = nil
			when "bug"
				report_vuln
			end
		end

		def report_vuln(&block)
			proto = @state[:url].split(":")[0]
			path = '/' + (@state[:url].split("/")[3..(@state[:url].split("/").length - 1)].join('/'))

			web_vuln_info = {}
			web_vuln_info[:web_site] = proto + "://" + @state[:host] + ":" + @state[:port]
			web_vuln_info[:path] = path
			web_vuln_info[:query] = @state[:url].split("?")[1]

			#if the URL contains the parameter found to be vulnerable, it is probably a GET
			#if it does not contains the parameter, it is probably a POST
			if @state[:url].index(@state[:parameter])
				web_vuln_info[:method] = "GET"
			else
				web_vuln_info[:method] = "POST"
			end

			@state[:parameter].split("&").each do |param|
				if param.index("%27") #apostrophe
					web_vuln_info[:pname] = param.split('=')[0] #sql injection
					break
				elsif param.index("alert")
					web_vuln_info[:pname] = param.split('=')[0] #xss
				end
			end

			web_vuln_info[:host] = @state[:host]
			web_vuln_info[:port] = @state[:port]
			web_vuln_info[:ssl] = (proto =~ /https/)
			web_vuln_info[:proof] = ""
			web_vuln_info[:risk] = ""
			web_vuln_info[:params] = @state[:parameter]
			web_vuln_info[:category] = "imported"
			web_vuln_info[:confidence] = 90
			web_vuln_info[:name] = @state[:info]

			db.emit(:web_vuln, web_vuln_info[:name], &block) if block
			vuln = db_report(:web_vuln, web_vuln_info)
		end
	end
end
end
