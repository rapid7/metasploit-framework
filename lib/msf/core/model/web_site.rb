module Msf
class DBManager

class WebSite < ActiveRecord::Base
	include DBSave
	belongs_to :service
	has_many :web_pages, :dependent => :destroy
	has_many :web_forms, :dependent => :destroy
	has_many :web_vulns, :dependent => :destroy

	serialize :options

	def to_url(ignore_vhost=false)
		proto = self.service.name == "https" ? "https" : "http"
		host  = ignore_vhost ? self.service.host.address : self.vhost
		port  = self.service.port
		
		if Rex::Socket.is_ipv6?(host)
			host = "[#{host}]"
		end
		
		url   = "#{proto}://#{host}"
		if not ((proto == "http" and port == 80) or (proto == "https" and port == 443))
			url += ":#{port}"
		end
		url
	end

	def page_count
		web_pages.size
	end

	def form_count
		web_forms.size
	end

	def vuln_count
		web_vulns.size
	end

end

end
end

