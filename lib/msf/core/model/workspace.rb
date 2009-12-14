module Msf
class DBManager

class Workspace < ActiveRecord::Base
	include DBSave

	DEFAULT = "default"

	has_many :hosts, :dependent => :destroy

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