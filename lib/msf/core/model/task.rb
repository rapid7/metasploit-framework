module Msf
class DBManager

class Task < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	serialize :options
end

end
end

