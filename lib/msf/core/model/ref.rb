module Msf
class DBManager

class Ref < ActiveRecord::Base
	include DBSave
	has_and_belongs_to_many :vulns, :join_table => :vulns_refs
end

end
end