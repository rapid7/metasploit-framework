module Msf
class DBManager

class Cred < ActiveRecord::Base
	include DBSave
	belongs_to :service
end

end
end
