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
# Straight up gangsta from spoon (ripped from BION)
module DBSave

	def self.included(mod)
		class << mod
			def find(*args)
				ActiveRecord::Base.connection_pool.clear_stale_cached_connections!
				super(*args)
			end

			def save(*args)
				ActiveRecord::Base.connection_pool.clear_stale_cached_connections!
				super(*args)
			end

		end
	end

end

end
end

