module Msf
class DBManager

class CredFile < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
end

end
end

