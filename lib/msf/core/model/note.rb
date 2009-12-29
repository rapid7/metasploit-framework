module Msf
class DBManager

class Note < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	belongs_to :host
	belongs_to :service

	serialize :data
end

end
end
