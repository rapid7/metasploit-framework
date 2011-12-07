module Msf
class DBManager

class Event < ActiveRecord::Base
	include DBSave
	belongs_to :workspace
	belongs_to :host
	serialize :info, Msf::Util::Base64Serializer.new
end

end
end

