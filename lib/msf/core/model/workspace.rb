require 'shellwords'
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
	has_many :imported_creds,  :dependent => :destroy
	has_many :exploited_hosts, :through => :hosts
	has_many :sessions, :through => :hosts
	has_many :cred_files, :dependent => :destroy
	has_many :listeners, :dependent => :destroy

	has_many :web_sites, :finder_sql =>
		'SELECT DISTINCT web_sites.* '           +
		'FROM hosts, services, web_sites '       +
		'WHERE hosts.workspace_id = #{id} AND '  +
			'services.host_id = hosts.id AND '   +
			'web_sites.service_id = services.id'

	has_many :web_pages, :finder_sql =>
		'SELECT DISTINCT web_pages.* '                +
		'FROM hosts, services, web_sites, web_pages ' +
		'WHERE hosts.workspace_id = #{id} AND '       +
			'services.host_id = hosts.id AND '        +
			'web_sites.service_id = services.id AND ' +
			'web_pages.web_site_id = web_sites.id'

	has_many :web_forms, :finder_sql =>
		'SELECT DISTINCT web_forms.* '                +
		'FROM hosts, services, web_sites, web_forms ' +
		'WHERE hosts.workspace_id = #{id} AND '       +
			'services.host_id = hosts.id AND '        +
			'web_sites.service_id = services.id AND ' +
			'web_forms.web_site_id = web_sites.id'

	has_many :unique_web_forms, :class_name => 'Msf::DBManager::WebForm', :finder_sql =>
		'SELECT DISTINCT web_forms.web_site_id, web_forms.path, web_forms.method, web_forms.query ' +
		'FROM hosts, services, web_sites, web_forms ' +
		'WHERE hosts.workspace_id = #{id} AND '       +
			'services.host_id = hosts.id AND '        +
			'web_sites.service_id = services.id AND ' +
			'web_forms.web_site_id = web_sites.id'

	has_many :web_vulns, :finder_sql =>
		'SELECT DISTINCT web_vulns.* '                +
		'FROM hosts, services, web_sites, web_vulns ' +
		'WHERE hosts.workspace_id = #{id} AND '       +
			'services.host_id = hosts.id AND '        +
			'web_sites.service_id = services.id AND ' +
			'web_vulns.web_site_id = web_sites.id'

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

	def host_tags
		Tag.find(
			:all,
			:include => :hosts,
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

	def each_host_tag(&block)
		host_tags.each do |host_tag|
			block.call(host_tag)
		end
	end

	def web_unique_forms(addrs=nil)
		forms = unique_web_forms
		if addrs
			forms.reject!{|f| not addrs.include?( f.web_site.service.host.address ) }
		end
		forms
	end

		#
	# If limit_to_network is disabled, this will always return true.
	# Otherwise, return true only if all of the given IPs are within the project
	# boundaries.
	#
	def allow_actions_on?(ips)
		return true unless limit_to_network
		return true unless boundary
		return true if boundary.empty?
		boundaries = Shellwords.split(boundary)
		return true if boundaries.empty? # It's okay if there is no boundary range after all
		given_range = Rex::Socket::RangeWalker.new(ips)
		return false unless given_range # Can't do things to nonexistant IPs
		allowed = false
		boundaries.each do |boundary_range|
			ok_range = Rex::Socket::RangeWalker.new(boundary)
			allowed = true if ok_range.include_range? given_range
		end
		return allowed
	end

end

end
end

