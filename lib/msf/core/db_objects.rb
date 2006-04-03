module Msf

##
#
# This module defines all of the DB database tables
# and creates ActiveRecord objects for each one of them
#
##

class DBManager

class Lock
	@@mutex = Mutex.new
	def self.mutex
		@@mutex
	end
end


# ActiveRecord/sqlite3 has locking issues when you update a table with a pending select
# This set of instance/class wrappers should prevent a table lock
module DBSave

	module InstanceMethods
		def save(*args)
			Lock.mutex.synchronize do
				super(*args)
			end
		end	
	end

	module ClassMethods
		def find(*args)
			Lock.mutex.synchronize do
				super(*args)
			end
		end	
	end

	def self::included(other)
		other.module_eval{ include InstanceMethods }
		other.extend ClassMethods
	end
end

# Host object definition
class Host < ActiveRecord::Base
	include DBSave
end

# Service object definition
class Service < ActiveRecord::Base
	include DBSave
		
	def host
		Host.find(:first, :conditions => [ "id = ?", host_id ])
	end
end

# Vuln object definition
class Vuln < ActiveRecord::Base
	include DBSave
	
	def service
		Service.find(:first, :conditions => [ "id = ?", service_id ])
	end
	
	def host
		Host.find(:first, :conditions => [ "id = ?", service.host_id ])
	end
end

end
end
