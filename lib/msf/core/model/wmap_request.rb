module Msf
class DBManager

# WMAP Request object definition
class WmapRequest < ::ActiveRecord::Base
	include DBSave
	# Magic.
end

end
end