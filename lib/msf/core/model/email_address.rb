module Msf
class DBManager

class EmailAddress < ActiveRecord::Base
	has_one :campaign
end

end
end
