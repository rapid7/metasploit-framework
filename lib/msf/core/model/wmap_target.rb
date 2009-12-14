module Msf
class DBManager

# WMAP Target object definition
class WmapTarget < ::ActiveRecord::Base
	include DBSave
	# Magic.
end

end
end