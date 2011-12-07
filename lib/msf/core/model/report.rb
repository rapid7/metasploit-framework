module Msf
class DBManager

class Report < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	serialize :options, Msf::Util::Base64Serializer.new
end

end
end

