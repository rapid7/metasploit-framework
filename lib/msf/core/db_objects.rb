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
# Straight up gangsta shit from spoon (ripped from BION)
module DBSave

# XXX: Removing the lock, may no longer be necessary
=begin
	def save(*args)
		Lock.mutex.synchronize do
			super(*args)
		end
	end	

	def self.included(mod)
		class << mod
			def find(*args)
				Lock.mutex.synchronize do
					super(*args)
				end
			end			
		end
	end
=end
end

# Host object definition
class Host < ActiveRecord::Base
	include DBSave
	has_many :services
	has_many :vulns, :through => :services
end

# Service object definition
class Service < ActiveRecord::Base
	include DBSave
	has_many :vulns
	belongs_to :host

	def host
		Host.find(:first, :conditions => [ "id = ?", host_id ])
	end	
end

# Vuln object definition
class Vuln < ActiveRecord::Base
	include DBSave
	belongs_to :service
	has_and_belongs_to_many :refs, :join_table => :vulns_refs

	def service
		Service.find(:first, :conditions => [ "id = ?", service_id ])
	end

	def host
		Host.find(:first, :conditions => [ "id = ?", service.host_id ])
	end
end

# Reference object definition
class Ref < ActiveRecord::Base
	include DBSave
	has_and_belongs_to_many :vulns, :join_table => :vulns_refs
end

# Reference object definition
class VulnRefs < ActiveRecord::Base
	set_table_name 'vulns_refs'
	include DBSave
end


# Service object definition
class Note < ActiveRecord::Base
	include DBSave
	belongs_to :host

	def host
		Host.find(:first, :conditions => [ "id = ?", host_id ])
	end	
end


# WMAP Request object definition	
class Request < ::ActiveRecord::Base
	include DBSave
	# Magic.
end

# WMAP Target object definition
class Target < ::ActiveRecord::Base
	include DBSave
	# Magic.
end

# WMAP Report object definition
class Report < ::ActiveRecord::Base
	include DBSave
end		

end
end
