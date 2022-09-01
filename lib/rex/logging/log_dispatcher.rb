# -*- coding: binary -*-
require 'rex/sync'

module Rex
module Logging

###
#
# The log dispatcher associates log sources with log sinks.  A log source
# is a unique identity that is associated with one and only one log sink.
# For instance, the framework-core registers the 'core'
#
###
class LogDispatcher

  #
  # Creates the global log dispatcher instance and initializes it for use.
  #
  def initialize()
    self.log_sinks      = {}
    self.log_levels     = {}
    self.log_sinks_lock = Mutex.new
  end

  #
  # Returns the sink that is associated with the supplied source.
  #
  def [](src)
    sink = nil

    log_sinks_lock.synchronize {
      sink = log_sinks[src]
    }

    return sink
  end

  #
  # Calls the source association routie.
  #
  def []=(src, sink)
    store(src, sink)
  end

  #
  # Associates the supplied source with the supplied sink.  If a log level
  # has already been defined for the source, the level argument is ignored.
  # Use set_log_level to alter it.
  #
  def store(src, sink, level = 0)
    log_sinks_lock.synchronize {
      if (log_sinks[src] == nil)
        log_sinks[src] = sink

        set_log_level(src, level) if (log_levels[src] == nil)
      else
        raise(
          RuntimeError,
          "The supplied log source #{src} is already registered.",
          caller)
      end
    }
  end

  #
  # Removes a source association if one exists.
  #
  def delete(src)
    sink = nil

    log_sinks_lock.synchronize {
      sink = log_sinks[src]

      log_sinks.delete(src)
    }

    if (sink)
      sink.cleanup

      return true
    end

    return false
  end

  #
  # Performs the actual log operation against the supplied source
  #
  def log(sev, src, level, msg)
    log_sinks_lock.synchronize {
      if ((sink = log_sinks[src]))
        next if (log_levels[src] and level > log_levels[src])

        sink.log(sev, src, level, msg)
      end
    }
  end

  #
  # This method sets the log level threshold for a given source.
  #
  def set_level(src, level)
    log_levels[src] = level.to_i
  end

  #
  # This method returns the log level threshold of a given source.
  #
  def get_level(src)
    log_levels.fetch(src, DEFAULT_LOG_LEVEL)
  end

  attr_accessor :log_sinks, :log_sinks_lock # :nodoc:
  attr_accessor :log_levels # :nodoc:
end

end
end

# An instance of the log dispatcher exists in the global namespace, along
# with stubs for many of the common logging methods.  Various sources can
# register themselves as a log sink such that logs can be directed at
# various targets depending on where they're sourced from.  By doing it
# this way, things like sessions can use the global logging stubs and
# still be directed at the correct log file.
#
###
ExceptionCallStack = "__EXCEPTCALLSTACK__"

BACKTRACE_LOG_LEVEL = 3 # Equal to LEV_3
DEFAULT_LOG_LEVEL = 0 # Equal to LEV_3

def dlog(msg, src = 'core', level = 0)
  $dispatcher.log(LOG_DEBUG, src, level, msg)
end

# Logs errors in a standard format for each Log Level.
#
# @param msg [String] Contains message from the developer explaining why an error was encountered.
# Can also be an +Exception+, in which case a log is built from the +Exception+ with no accompanying message.
#
# @param src [String] Used to indicate where the error is originating from. Most commonly set to 'core'.
#
# @param log_level [Integer] Indicates the level of logging the message should be recorded at. If log_level is greater than
# the global log level set for +src+, then the log is not recorded.
#
# @param error [Exception] Exception of an error that needs to be logged. For all log messages, the class and message of
# an exception is added to a log message. If the global log level set for +src+ is greater than +BACKTRACE_LOG_LEVEL+,
# then the stack trace for an error is also added to the log message.
#
# (Eg Loop Iterations, Variables, Function Calls).
#
# @return [NilClass].
def elog(msg, src = 'core', log_level = 0, error: nil)
  error = msg.is_a?(Exception) ? msg : error

  if error.nil? || !error.is_a?(Exception)
    $dispatcher.log(LOG_ERROR, src, log_level, msg)
  else
    error_details = "#{error.class} #{error.message}"
    if get_log_level(src) >= BACKTRACE_LOG_LEVEL
      if error.backtrace
        error_details << "\nCall stack:\n#{error.backtrace.join("\n")}"
      else
        error_details << "\nCall stack:\nNone"
      end
    end

    if msg.is_a?(Exception)
      $dispatcher.log(LOG_ERROR, src, log_level,"#{error_details}")
    else
      $dispatcher.log(LOG_ERROR, src, log_level,"#{msg} - #{error_details}")
    end
  end
end

def wlog(msg, src = 'core', level = 0)
  $dispatcher.log(LOG_WARN, src, level, msg)
end

def ilog(msg, src = 'core', level = 0)
  $dispatcher.log(LOG_INFO, src, level, msg)
end

def rlog(msg, src = 'core', level = 0)
  if (msg == ExceptionCallStack)
    msg = "\nCall stack:\n" + $@.join("\n") + "\n"
  end

  $dispatcher.log(LOG_RAW, src, level, msg)
end

def log_source_registered?(src)
  ($dispatcher[src] != nil)
end

def register_log_source(src, sink, level = nil)
  $dispatcher[src] = sink

  set_log_level(src, level) if (level)
end

def deregister_log_source(src)
  $dispatcher.delete(src)
end

def set_log_level(src, level)
  $dispatcher.set_level(src, level)
end

def get_log_level(src)
  $dispatcher.get_level(src)
end

# Creates the global log dispatcher
$dispatcher = Rex::Logging::LogDispatcher.new
