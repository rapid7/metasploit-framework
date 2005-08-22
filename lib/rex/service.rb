require 'rex'

require 'rex'
require 'rex/proto'

module Rex

###
#
# Service
# -------
#
# The service module is used to extend classes that are passed into the
# service manager start routine.  It provides extra methods, such as reference
# counting, that are used to track the service instances more uniformly.
#
###
module Service
	include Ref
end

end
