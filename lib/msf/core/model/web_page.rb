module Msf
class DBManager

class WebPage < ActiveRecord::Base
	include DBSave
	belongs_to :web_site
	serialize :headers, Msf::Util::Base64Serializer.new
end

end
end

