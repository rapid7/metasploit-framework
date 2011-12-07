module Msf
class DBManager

class Profile < ActiveRecord::Base
	include DBSave
	serialize :settings, Msf::Util::Base64Serializer.new
end

end
end

