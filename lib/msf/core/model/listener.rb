module Msf
class DBManager

class Listener < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	belongs_to :task

	serialize :options, Msf::Util::Base64Serializer.new
end

end
end

