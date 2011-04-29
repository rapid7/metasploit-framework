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


#
# This inclusion makes sure the connection pool of ActiveRecord is purged frequently
#
module DBSave

	def self.included(mod)
		class << mod
			def find(*args)
				ActiveRecord::Base.connection_pool.clear_stale_cached_connections! if ActiveRecord::Base.connection_pool
				super(*args)
			end

			def save(*args)
				ActiveRecord::Base.connection_pool.clear_stale_cached_connections! if ActiveRecord::Base.connection_pool
				super(*args)
			end

		end
	end

end

end
end

