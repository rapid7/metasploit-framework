module Msf
class DBManager

class Host < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	has_many :services, :dependent => :destroy
	has_many :clients,  :dependent => :destroy
	has_many :vulns,    :dependent => :destroy
	has_many :notes,    :dependent => :destroy

	has_many :service_notes, :through => :services

	validates_exclusion_of :address, :in => ['127.0.0.1']
	validates_uniqueness_of :address, :scope => :workspace_id
end

end
end
