module Msf
class DBManager

class Session < ActiveRecord::Base
	has_one :host
	serialize :datastore
	serialize :routes
end

end
end
