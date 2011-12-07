module Msf
class DBManager

class User < ActiveRecord::Base
	include DBSave

	serialize :prefs, Msf::Util::Base64Serializer.new
end

end
end

