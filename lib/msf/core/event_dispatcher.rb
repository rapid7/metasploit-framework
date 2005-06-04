require 'Msf/Core'

module Msf

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
		self.exploit_event_subscribers = []
		self.session_event_subscribers = []
		self.recon_event_subscribers   = []
		self.subscribers_rwlock        = Rex::ReadWriteLock.new
	end

	#
	# Subscriber registration
	#

	def add_recon_subscriber(subscriber)
		add_event_subscriber(recon_event_subscribers, subscriber)
	end

	def remove_recon_subscriber(subscriber)
		remove_event_subscriber(recon_event_subscribers, subscriber)
	end

	def add_exploit_subscriber(subscriber)
		add_event_subscriber(exploit_event_subscribers, subscriber)
	end

	def remove_exploit_subscriber(subscriber)
		remove_event_subscriber(exploit_event_subscribers, subscriber)
	end

	def add_session_subscriber(subscriber)
		add_event_subscriber(session_event_subscribers, subscriber)
	end

	def remove_session_subscriber(subscriber)
		remove_event_subscriber(session_event_subscribers, subscriber)
	end

	#
	# Event dispatching entry point
	#

	def on_recon_discovery(group, info)
		subscribers_rwlock.synchronize_read {
			recon_event_subscribers.each { |subscriber|
				subscriber.on_recon_discovery(group, info)
			}
		}
	end

	def on_exploit_success(exploit, target)
		subscribers_rwlock.synchronize_read {
			exploit_event_subscribers.each { |subscriber|
				subscriber.on_exploit_success(exploit, target)
			}
		}
	end

	def on_exploit_failure(exploit, target)
		subscribers_rwlock.synchronize_read {
			exploit_event_subscribers.each { |subscriber|
				subscriber.on_exploit_failure(exploit, target)
			}
		}
	end

	def on_session_open(session)
		subscribers_rwlock.synchronize_read {
			session_event_subscribers.each { |subscriber|
				subscriber.on_session_open(session)
			}
		}
	end

	def on_session_close(session)
		subscribers_rwlock.synchronize_read {
			session_event_subscribers.each { |subscriber|
				subscriber.on_session_close(session)
			}
		}
	end

protected

	def add_event_subscriber(array, subscriber)
		subscribers_rwlock.synchronize_write {
			array << subscriber
		}
	end

	def remove_event_subscriber(array, subscriber)
		subscribers_rwlock.synchronize_write {
			array.delete(subscriber)
		}
	end

	attr_accessor :exploit_event_subscribers
	attr_accessor :session_event_subscribers
	attr_accessor :recon_event_subscribers
	attr_accessor :subscribers_rwlock

end

end
