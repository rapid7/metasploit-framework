require 'msf/core'

module Msf

###
#
# This event subscriber class exposes methods that are called when internal
# framework events occur, such as the loading and creation of a module.
#
###
module GeneralEventSubscriber
	#
	# Called when a module is loaded
	#
	def on_module_load(refname, klass)
	end

	#
	# Called when a new module instance is created
	#
	def on_module_created(instance)
	end
end

###
#
# This class manages subscriber registration and is the entry point
# for dispatching various events that occur for modules, such as
# exploit results and auxiliary module data. The framework
# and external modules can register themselves as subscribers to
# various events such that they can perform custom actions when
# a specific event or events occur.
#
###
class EventDispatcher

	include Framework::Offspring

	def initialize(framework)
		self.framework = framework
		self.general_event_subscribers = []
		self.exploit_event_subscribers = []
		self.session_event_subscribers = []
		self.db_event_subscribers      = []
	end

	##
	#
	# Subscriber registration
	#
	##

	#
	# This method adds a general subscriber.  General subscribers receive
	# notifications when all events occur.
	#
	def add_general_subscriber(subscriber)
		add_event_subscriber(general_event_subscribers, subscriber)
	end

	#
	# Removes a general subscriber.
	#
	def remove_general_subscriber(subscriber)
		remove_event_subscriber(general_event_subscribers, subscriber)	
	end

	#
	# This method adds a db event subscriber. db event subscribers
	# receive notifications when events occur that pertain to db changes.
	# The subscriber provided must implement the DatabaseEvent module methods
	# in some form.
	#
	def add_db_subscriber(subscriber)
		add_event_subscriber(db_event_subscribers, subscriber)
	end

	#
	# Removes a db event subscriber.
	#
	def remove_db_subscriber(subscriber)
		remove_event_subscriber(db_event_subscribers, subscriber)
	end


	#
	# This method adds an exploit event subscriber.  Exploit event subscribers
	# receive notifications when events occur that pertain to exploits, such as
	# the success or failure of an exploitation attempt.  The subscriber
	# provided must implement the ExploitEvents module methods in some form.
	#
	def add_exploit_subscriber(subscriber)
		add_event_subscriber(exploit_event_subscribers, subscriber)
	end

	#
	# Removes an exploit event subscriber.
	#
	def remove_exploit_subscriber(subscriber)
		remove_event_subscriber(exploit_event_subscribers, subscriber)
	end

	#
	# This method adds a session event subscriber.  Session event subscribers
	# receive notifications when sessions are opened and closed.  The
	# subscriber provided must implement the SessionEvents module methods in
	# some form.
	#
	def add_session_subscriber(subscriber)
		add_event_subscriber(session_event_subscribers, subscriber)
	end

	#
	# Removes a session event subscriber.
	#
	def remove_session_subscriber(subscriber)
		remove_event_subscriber(session_event_subscribers, subscriber)
	end

	##
	#
	# General events
	#
	##

	#
	# Called when a module is loaded into the framework.  This, in turn,
	# notifies all registered general event subscribers.
	#
	def on_module_load(name, mod)
		general_event_subscribers.each { |subscriber|
			subscriber.on_module_load(name, mod)
		}
	end

	#
	# Called when a module is unloaded from the framework.  This, in turn,
	# notifies all registered general event subscribers.
	#
	def on_module_created(instance)
		general_event_subscribers.each { |subscriber|
			subscriber.on_module_created(instance)
		}
	end
	
	#
	# Capture incoming events and pass them off to the subscribers
	#
	def method_missing(name, *args)

		case name.to_s

		# Exploit events
		when /^on_exploit/
			exploit_event_subscribers.each do |subscriber|
				next if not subscriber.respond_to?(name)
				subscriber.send(name, *args)
			end

		# Session events
		when /^on_session/
			session_event_subscribers.each do |subscriber|
				next if not subscriber.respond_to?(name)
				subscriber.send(name, *args)
			end

		# db events
		when /^on_db/
			# Only process these events if the db is active
			if (framework.db.active)
				db_event_subscribers.each do |subscriber|
					next if not subscriber.respond_to?(name)
					subscriber.send(name, *args)
				end
			end
		# Everything else								
		else
			elog("Event dispatcher received an unhandled event: #{name}")
			return false
		end		

		return true
	end
	
	
protected

	#
	# Adds an event subscriber to the supplied subscriber array.
	#
	def add_event_subscriber(array, subscriber) # :nodoc:
		array << subscriber
	end

	#
	# Removes an event subscriber from the supplied subscriber array.
	#
	def remove_event_subscriber(array, subscriber) # :nodoc:
		array.delete(subscriber)
	end

	attr_accessor :general_event_subscribers # :nodoc:
	attr_accessor :exploit_event_subscribers # :nodoc:
	attr_accessor :session_event_subscribers # :nodoc:
	attr_accessor :db_event_subscribers # :nodoc:	

end

end
