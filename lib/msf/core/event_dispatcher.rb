require 'msf/core'

module Msf

###
#
# GeneralEventSubscriber
# ----------------------
#
# Called when internal framework events occur.
#
###
module GeneralEventSubscriber
	#
	# Called when a module is loaded
	#
	attr_accessor :on_module_load_proc
	#
	# Called when a new module instance is created
	#
	attr_accessor :on_module_created_proc
end

###
#
# EventDispatcher
# ---------------
#
# This class manages subscriber registration and is the entry point
# for dispatching various events that occur for modules, such as
# recon discovery and exploit success or failure.  The framework
# and external modules can register themselves as subscribers to
# various events such that they can perform custom actions when
# a specific event or events occur.
#
###
class EventDispatcher

	def initialize
		self.general_event_subscribers = []
		self.exploit_event_subscribers = []
		self.session_event_subscribers = []
		self.recon_event_subscribers   = []
		self.subscribers_rwlock        = Rex::ReadWriteLock.new
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
	# This method adds a recon event subscriber.  Recon event subscribers
	# receive notifications when events occur that pertain to recon modules.
	# The subscriber provided must implement the ReconEvents module methods in
	# some form.
	#
	def add_recon_subscriber(subscriber)
		add_event_subscriber(recon_event_subscribers, subscriber)
	end

	#
	# Removes a recon event subscriber.
	#
	def remove_recon_subscriber(subscriber)
		remove_event_subscriber(recon_event_subscribers, subscriber)
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
		subscribers_rwlock.synchronize_read {
			general_event_subscribers.each { |subscriber|
				next if (!subscriber.on_module_load_proc)

				subscriber.on_module_load_proc.call(name, mod)
			}
		}
	end

	#
	# Called when a module is unloaded from the framework.  This, in turn,
	# notifies all registered general event subscribers.
	#
	def on_module_created(instance)
		subscribers_rwlock.synchronize_read {
			general_event_subscribers.each { |subscriber|
				next if (!subscriber.on_module_created_proc)

				subscriber.on_module_created_proc.call(instance)
			}
		}
	end

	##
	#
	# Recon events
	#
	##

	#
	# This routine is called whenever a host's state changes, such as when it's
	# added, updated, or removed.  This event is dispatched by the Recon
	# Manager once it makes a determination on the accurate state of a host as
	# provided by one or more host recon modules.
	#
	def on_host_changed(context, host, change_type)
		subscribers_rwlock.synchronize_read {
			recon_event_subscribers.each { |subscriber|
				next if (subscriber.include?(Msf::ReconEvent::HostSubscriber) == false)

				subscriber.on_host_changed(context, host, change_type)
			}
		}
	end

	#
	# This routine is called whenever a service's state changes, such as when
	# it's found, updated, or removed.  This event is dispatched by the Recon
	# Manager.
	#
	def on_service_changed(context, host, service, change_type)
		subscribers_rwlock.synchronize_read {
			recon_event_subscribers.each { |subscriber|
				next if (subscriber.include?(Msf::ReconEvent::ServiceSubscriber) == false)

				subscriber.on_service_changed(context, host, service, change_type)
			}
		}
	end

	##
	#
	# Exploit events
	#
	##

	#
	# Called when an exploit succeeds.  This notifies the registered exploit
	# event subscribers.
	#
	def on_exploit_success(exploit, session = nil)
		subscribers_rwlock.synchronize_read {
			exploit_event_subscribers.each { |subscriber|
				subscriber.on_exploit_success(exploit, session)
			}
		}
	end

	#
	# Called when an exploit fails.  This notifies the registered exploit
	# event subscribers.
	#
	def on_exploit_failure(exploit, reason)
		subscribers_rwlock.synchronize_read {
			exploit_event_subscribers.each { |subscriber|
				subscriber.on_exploit_failure(exploit, reason)
			}
		}
	end

	##
	#
	# Session events
	#
	##

	#
	# Called when a new session is opened.  This notifies all the registered
	# session event subscribers.
	#
	def on_session_open(session)
		subscribers_rwlock.synchronize_read {
			session_event_subscribers.each { |subscriber|
				subscriber.on_session_open(session)
			}
		}
	end

	#
	# Called when a new session is closed.  This notifies all the registered
	# session event subscribers.
	#
	def on_session_close(session)
		subscribers_rwlock.synchronize_read {
			session_event_subscribers.each { |subscriber|
				subscriber.on_session_close(session)
			}
		}
	end

protected

	#
	# Adds an event subscriber to the supplied subscriber array.
	#
	def add_event_subscriber(array, subscriber) # :nodoc:
		subscribers_rwlock.synchronize_write {
			array << subscriber
		}
	end

	#
	# Removes an event subscriber from the supplied subscriber array.
	#
	def remove_event_subscriber(array, subscriber) # :nodoc:
		subscribers_rwlock.synchronize_write {
			array.delete(subscriber)
		}
	end

	attr_accessor :general_event_subscribers
	attr_accessor :exploit_event_subscribers
	attr_accessor :session_event_subscribers
	attr_accessor :recon_event_subscribers
	attr_accessor :subscribers_rwlock

end

end
