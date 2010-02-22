module Msf
class DBManager

class User < ActiveRecord::Base
	include DBSave
end

end
end

