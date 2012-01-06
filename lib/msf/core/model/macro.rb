module Msf
class DBManager

class Macro < ActiveRecord::Base
	include DBSave
	serialize :actions
	serialize :prefs
end

end
end

