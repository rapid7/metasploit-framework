module Msf
class DBManager

class WebVuln < ActiveRecord::Base
	include DBSave
	belongs_to :web_site
	serialize :params, Msf::Util::Base64Serializer.new
end

end
end

