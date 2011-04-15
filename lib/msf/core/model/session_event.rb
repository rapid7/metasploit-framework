module Msf
class DBManager

class SessionEvent < ActiveRecord::Base
	include DBSave

	belongs_to :session
end

end
end
