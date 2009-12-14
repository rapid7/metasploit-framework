module Msf
class DBManager

class Client < ActiveRecord::Base
	include DBSave
	belongs_to :host
end

end
end