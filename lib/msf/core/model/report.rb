module Msf
class DBManager

class Report < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	serialize :options
end

end
end

