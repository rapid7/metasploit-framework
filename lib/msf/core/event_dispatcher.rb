# -*- coding: binary -*-
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

  #
  # Called when a module is run
  #
  def on_module_run(instance)
  end

  #
  # Called when a module finishes
  #
  def on_module_complete(instance)
  end

  #
  # Called when a module raises an exception
  #
  def on_module_error(instance, exception)
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
    self.custom_event_subscribers  = []
    self.exploit_event_subscribers = []
    self.session_event_subscribers = []
    self.db_event_subscribers      = []
    self.ui_event_subscribers      = []
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
  # provided must implement the ExploitEvent module methods in some form.
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
  # subscriber provided must implement the SessionEvent module methods in
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
  # This is covered by the method_missing logic, but defining it manually
  # reduces startup time by about 10%.
  #
  def on_module_load(name, mod)
    general_event_subscribers.each { |subscriber|
      subscriber.on_module_load(name, mod)
    }
  end

  #
  # Capture incoming events and pass them off to the subscribers
  #
  # When receiving an on_* event, look for a subscriber type matching the
  # type of the event.  If one exists, send the event on to each subscriber
  # of that type.  Otherwise, try to send the event each of the general
  # subscribers.
  #
  # Event method names should be like "on_<type>_<event>", e.g.:
  # on_exploit_success.
  #
  def method_missing(name, *args)

    event,type,rest = name.to_s.split("_", 3)
    subscribers = "#{type}_event_subscribers"
    found = false
    case event
    when "on"
      if respond_to?(subscribers)
        found = true
        self.send(subscribers).each do |sub|
          next if not sub.respond_to?(name)
          sub.send(name, *args)
        end
      else
        (general_event_subscribers + custom_event_subscribers).each do |sub|
          next if not sub.respond_to?(name)
          sub.send(name, *args)
          found = true
        end
      end
    when "add"
      if respond_to?(subscribers)
        found = true
        add_event_subscriber(self.send(subscribers), *args)
      end
    when "remove"
      if respond_to?(subscribers)
        found = true
        remove_event_subscriber(self.send(subscribers), *args)
      end
    end

    return found
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
  attr_accessor :custom_event_subscribers # :nodoc:
  attr_accessor :exploit_event_subscribers # :nodoc:
  attr_accessor :session_event_subscribers # :nodoc:
  attr_accessor :db_event_subscribers # :nodoc:
  attr_accessor :ui_event_subscribers # :nodoc:

end

end
