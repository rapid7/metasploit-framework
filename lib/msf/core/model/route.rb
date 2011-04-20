module Msf
class DBManager

class Route < ActiveRecord::Base
	belongs_to :session
end

end
end
