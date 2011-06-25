module Msf
class DBManager

class Listener < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	belongs_to :task

	serialize :options
end

end
end

