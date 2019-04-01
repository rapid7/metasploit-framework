# -*- coding: binary -*-

require 'shellwords'

module Msf
  module Sessions
    #
    # Defines common options across all Meterpreter implementations
    #
    module MeterpreterOptions

      TIMEOUT_SESSION = 24 * 3600 * 7  # 1 week
      TIMEOUT_COMMS = 300              # 5 minutes
      TIMEOUT_RETRY_TOTAL = 60 * 60    # 1 hour
      TIMEOUT_RETRY_WAIT = 10          # 10 seconds

      def initialize(info = {})
        super(info)

        register_advanced_options(
          [
            OptBool.new(
              'AutoLoadStdapi',
              [true, "Automatically load the Stdapi extension", true]
            ),
            OptBool.new(
              'AutoVerifySession',
              [true, "Automatically verify and drop invalid sessions", true]
            ),
            OptInt.new(
              'AutoVerifySessionTimeout',
              [false, "Timeout period to wait for session validation to occur, in seconds", 30]
            ),
            OptString.new(
              'InitialAutoRunScript',
              [false, "An initial script to run on session creation (before AutoRunScript)", '']
            ),
            OptString.new(
              'AutoRunScript',
              [false, "A script to run automatically on session creation.", '']
            ),
            OptBool.new(
              'AutoSystemInfo',
              [true, "Automatically capture system information on initialization.", true]
            ),
            OptBool.new(
              'EnableUnicodeEncoding',
              [true, "Automatically encode UTF-8 strings as hexadecimal", Rex::Compat.is_windows]
            ),
            OptPath.new(
              'HandlerSSLCert',
              [false, "Path to a SSL certificate in unified PEM format, ignored for HTTP transports"]
            ),
            OptInt.new(
              'SessionRetryTotal',
              [false, "Number of seconds try reconnecting for on network failure", TIMEOUT_RETRY_TOTAL]
            ),
            OptInt.new(
              'SessionRetryWait',
              [false, "Number of seconds to wait between reconnect attempts", TIMEOUT_RETRY_WAIT]
            ),
            OptInt.new(
              'SessionExpirationTimeout',
              [ false, 'The number of seconds before this session should be forcibly shut down', TIMEOUT_SESSION]
            ),
            OptInt.new(
              'SessionCommunicationTimeout',
              [ false, 'The number of seconds of no activity before this session should be killed', TIMEOUT_COMMS]
            ),
            OptString.new(
              'PayloadProcessCommandLine',
              [ false, 'The displayed command line that will be used by the payload', '']
            ),
            OptBool.new(
              'AutoUnhookProcess',
              [true, "Automatically load the unhook extension and unhook the process", false]
            ),
          ],
          self.class
        )
      end
    end
  end
end
