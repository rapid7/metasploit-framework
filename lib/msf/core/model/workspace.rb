module Msf
class DBManager

class Workspace < ActiveRecord::Base
	include DBSave

	DEFAULT = "default"

	has_many :hosts, :dependent => :destroy
	has_many :notes, :dependent => :destroy
	has_many :loots, :dependent => :destroy
	has_many :events,:dependent => :destroy
	has_many :reports, :dependent => :destroy

	has_many :services, :through => :hosts
	has_many :clients,  :through => :hosts
	has_many :vulns,    :through => :hosts


	#has_many :notes,    :through => :hosts

	validates_uniqueness_of :name
	validates_presence_of :name

	def self.default
		Workspace.find_or_create_by_name(DEFAULT)
	end

	def default?
		name == DEFAULT
	end
end

end
end

