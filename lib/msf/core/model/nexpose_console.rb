module Msf
class DBManager

class NexposeConsole < ActiveRecord::Base
	include DBSave
	serialize :cached_sites, Msf::Util::Base64Serializer.new
end

end
end

