module Msf
class DBManager

class Macro < ActiveRecord::Base
	include DBSave
	serialize :actions, Msf::Util::Base64Serializer.new
	serialize :prefs, Msf::Util::Base64Serializer.new
end

end
end

