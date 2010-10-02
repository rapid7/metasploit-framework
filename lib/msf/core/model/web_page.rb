module Msf
class DBManager

class WebPage < ActiveRecord::Base
	include DBSave
	belongs_to :web_site
	serialize :headers
end

end
end

