module Msf
class DBManager

class ImportedCred < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
end

end
end

