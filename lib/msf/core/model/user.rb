module Msf
class DBManager

class User < ActiveRecord::Base
	include DBSave

	serialize :prefs
end

end
end

