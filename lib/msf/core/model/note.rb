module Msf
class DBManager

class Note < ActiveRecord::Base
	include DBSave
	belongs_to :host
end

end
end