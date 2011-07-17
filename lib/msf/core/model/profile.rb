module Msf
class DBManager

class Profile < ActiveRecord::Base
	include DBSave
	serialize :settings
end

end
end

