module Msf
class DBManager

class Event < ActiveRecord::Base
	include DBSave
	belongs_to :workspace
	belongs_to :host

	serialize :info
end

end
end
