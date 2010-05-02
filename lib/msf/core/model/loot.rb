module Msf
class DBManager

class Loot < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	belongs_to :host
	belongs_to :service

	serialize :data
end

end
end

