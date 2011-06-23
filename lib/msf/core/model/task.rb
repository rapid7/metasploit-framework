module Msf
class DBManager

class Task < ActiveRecord::Base
	include DBSave

	belongs_to :workspace

	serialize :options
	serialize :result
	serialize :settings
end

end
end

