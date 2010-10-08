module Msf
class DBManager

class Client < ActiveRecord::Base
	include DBSave
	belongs_to :host
	belongs_to :campaign
end

end
end
