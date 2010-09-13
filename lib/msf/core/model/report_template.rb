module Msf
class DBManager

class ReportTemplate < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
end

end
end

