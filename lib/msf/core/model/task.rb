module Msf
class DBManager

class Task < ActiveRecord::Base
	include DBSave

	belongs_to :workspace

	serialize :options, Msf::Util::Base64Serializer.new
	serialize :result, Msf::Util::Base64Serializer.new
	serialize :settings, Msf::Util::Base64Serializer.new
end

end
end

