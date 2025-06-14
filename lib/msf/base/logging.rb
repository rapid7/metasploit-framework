# -*- coding: binary -*-
require 'rex'
module Msf

# This module provides an initialization interface for logging.
class Logging

  #Is logging initialized
  #@private
  @@initialized = false
  #Is session logging enabled
  #@private
  @@session_logging = false

  # Initialize logging.
  #
  # @param log_sink_name [string] Log sink name.
  # @return [void]
  def self.init(log_sink_name = nil)
    if (! @@initialized)
      @@initialized = true

      log_sink ||= Rex::Logging::LogSinkFactory.new(
        log_sink_name,
        Msf::Config.log_directory + File::SEPARATOR + "framework.log"
      )

      # Register each known log source
      [
        Rex::LogSource,
        Rex::Socket::LogSource,
        Msf::LogSource,
        'base',
      ].each { |src|
        register_log_source(src, log_sink)
      }
    end
  end

  # Enables a log source of name src. Creates the .log file in the
  # configured directory if logging is not already enabled for this
  # source.
  #
  # @param src [String] log source name.
  # @param level [Integer] logging level.
  # @return [void]
  def self.enable_log_source(src, level = 0)
    if (log_source_registered?(src) == false)
      f = Rex::Logging::Sinks::Flatfile.new(
        Msf::Config.log_directory + File::SEPARATOR + "#{src}.log")

      register_log_source(src, f, level)
    end
  end

  # Stops logging for a given log source.
  #
  # @param src [String] the log source to disable.
  # @return [Boolean] true if successful. false if not.
  def self.disable_log_source(src)
    deregister_log_source(src)
  end

  # Sets whether or not session logging is to be enabled.
  #
  # @param tf [Boolean] true if enabling. false if disabling.
  # @return [void]
  def self.enable_session_logging(tf)
    @@session_logging = tf
  end

  # Returns whether or not session logging is enabled.
  #
  # @return [Boolean] true if enabled. false if disabled.
  def self.session_logging_enabled?
    @@session_logging || false
  end

  # Starts logging for a given session.
  #
  # @param session [Msf::Session] the session to start logging on.
  # @return [void]
  def self.start_session_log(session)
    if (log_source_registered?(session.log_source) == false)
      f = Rex::Logging::Sinks::TimestampColorlessFlatfile.new(
      Msf::Config.session_log_directory + File::SEPARATOR + "#{session.log_file_name}.log")

      register_log_source(session.log_source, f)

      rlog("\n[*] Logging started: #{Time.now}\n\n", session.log_source)
    end
  end

  # Stops logging for a given session.
  #
  # @param session [Msf::Session] the session to stop logging.
  # @return [Boolean] true if successful. false if not.
  def self.stop_session_log(session)
    rlog("\n[*] Logging stopped: #{Time.now}\n\n", session.log_source)

    deregister_log_source(session.log_source)
  end

end

end
