module Msf
class DBManager

class Workspace < ActiveRecord::Base
	include DBSave

	DEFAULT = "default"

	has_many :hosts, :dependent => :destroy
	has_many :services, :through => :hosts
	has_many :notes, :dependent => :destroy
	has_many :loots, :dependent => :destroy
	has_many :events,:dependent => :destroy
	has_many :reports, :dependent => :destroy
	has_many :report_templates, :dependent => :destroy
	has_many :tasks,   :dependent => :destroy
	has_many :clients,  :through => :hosts
	has_many :vulns,    :through => :hosts
	has_many :creds,    :dependent => :destroy
	has_many :exploited_hosts, :through => :hosts


	validates_uniqueness_of :name
	validates_presence_of :name

	def self.default
		Workspace.find_or_create_by_name(DEFAULT)
	end

	def default?
		name == DEFAULT
	end

	def creds
		Cred.find(
			:all,
			:include => {:service => :host}, # That's some magic right there.
			:conditions => ["hosts.workspace_id = ?", self.id]
		)
	end

	#
	# This method iterates the creds table calling the supplied block with the
	# cred instance of each entry.
	#
	def each_cred(&block)
		creds.each do |cred|
			block.call(cred)
		end
	end

	def web_sites
		hosts.map{|host| host.web_sites}.flatten
	end

	def web_pages
		web_sites.map{|w| w.web_pages}.flatten
	end

	def web_forms
		web_sites.map{|w| w.web_forms}.flatten
	end

	def web_vulns
		web_sites.map{|w| w.web_vulns}.flatten
	end
	
	def web_unique_forms
		cache = {}
		web_forms.each do |form|
			ckey = [ form.web_site.id, form.path, form.method, form.query].join("|")
			cache[ckey] = form
		end
		cache.values
	end

end

end
end

