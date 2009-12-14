module Msf
class DBManager

class Vuln < ActiveRecord::Base
	include DBSave
	belongs_to :host
	belongs_to :service
	has_and_belongs_to_many :refs, :join_table => :vulns_refs
end

end
end