module Msf
class DBManager

class WebSite < ActiveRecord::Base
	include DBSave
	belongs_to :service
	has_many :web_pages, :dependent => :destroy
	has_many :web_forms, :dependent => :destroy
	has_many :web_vulns, :dependent => :destroy
			
	serialize :options
end

end
end

