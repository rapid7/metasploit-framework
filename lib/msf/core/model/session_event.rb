module Msf
class DBManager

	# TODO: needs a belongs_to :session when that model gets committed.

class SessionEvent < ActiveRecord::Base
	include DBSave
end

end
end
