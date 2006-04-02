module Msf


##
#
# This module defines all of the DB database tables
# and creates ActiveRecord objects for each one of them
#
##

class DBManager

# Host object definition
class Host < ActiveRecord::Base
end

# Service object definition
class Service < ActiveRecord::Base
	def host
		Host.find(:first, :conditions => [ "id = ?", host_id ])
	end
end

# Vuln object definition
class Vuln < ActiveRecord::Base
	def service
		Service.find(:first, :conditions => [ "id = ?", service_id ])
	end
	
	def host
		Host.find(:first, :conditions => [ "id = ?", service.host_id ])
	end
end

end
end
