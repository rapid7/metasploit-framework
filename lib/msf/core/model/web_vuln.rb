module Msf
class DBManager

class WebVuln < ActiveRecord::Base
	include DBSave
	belongs_to :web_site
	serialize :params
end

end
end

