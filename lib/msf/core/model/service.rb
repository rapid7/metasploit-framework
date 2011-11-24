module Msf
class DBManager

class Service < ActiveRecord::Base
	include DBSave
	has_many :vulns, :dependent => :destroy
	has_many :notes, :dependent => :destroy
	has_many :creds, :dependent => :destroy
	has_many :exploited_hosts, :dependent => :destroy
	has_many :web_sites, :dependent => :destroy
	belongs_to :host

	has_many :web_pages, :through => :web_sites
	has_many :web_forms, :through => :web_sites
	has_many :web_vulns, :through => :web_sites

	serialize :info

	def after_save
		if info_changed?
			host.normalize_os
		end
	end

end

end
end

