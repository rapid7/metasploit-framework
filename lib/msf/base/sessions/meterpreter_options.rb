# -*- coding: binary -*-

require 'shellwords'

module Msf
module Sessions
module MeterpreterOptions

  def initialize(info = {})
    super(info)

    register_advanced_options(
      [
        OptBool.new('AutoLoadStdapi', [true, "Automatically load the Stdapi extension", true]),
        OptBool.new('AutoVerifySession', [true, "Automatically verify and drop invalid sessions", true]),
        OptInt.new('AutoVerifySessionTimeout', [false, "Timeout period to wait for session validation to occur, in seconds", 30]),
        OptString.new('InitialAutoRunScript', [false, "An initial script to run on session creation (before AutoRunScript)", '']),
        OptString.new('AutoRunScript', [false, "A script to run automatically on session creation.", '']),
        OptBool.new('AutoSystemInfo', [true, "Automatically capture system information on initialization.", true]),
        OptBool.new('EnableUnicodeEncoding', [true, "Automatically encode UTF-8 strings as hexadecimal", Rex::Compat.is_windows]),
        OptPath.new('HandlerSSLCert', [false, "Path to a SSL certificate in unified PEM format, ignored for HTTP transports"]),
        OptInt.new('SessionRetryTotal', [false, "Number of seconds try reconnecting for on network failure", Rex::Post::Meterpreter::ClientCore::TIMEOUT_RETRY_TOTAL]),
        OptInt.new('SessionRetryWait', [false, "Number of seconds to wait between reconnect attempts", Rex::Post::Meterpreter::ClientCore::TIMEOUT_RETRY_WAIT]),
        OptInt.new('SessionExpirationTimeout', [ false, 'The number of seconds before this session should be forcibly shut down', Rex::Post::Meterpreter::ClientCore::TIMEOUT_SESSION]),
        OptInt.new('SessionCommunicationTimeout', [ false, 'The number of seconds of no activity before this session should be killed', Rex::Post::Meterpreter::ClientCore::TIMEOUT_COMMS])
      ], self.class)
  end

  #
  # Once a session is created, automatically load the stdapi extension if the
  # advanced option is set to true.
  #
  def on_session(session)
    super

    # Defer the session initialization to the Session Manager scheduler
    framework.sessions.schedule Proc.new {

    # Configure unicode encoding before loading stdapi
    session.encode_unicode = datastore['EnableUnicodeEncoding']

    session.init_ui(self.user_input, self.user_output)

    valid = true

    if datastore['AutoVerifySession']
      if not session.is_valid_session?(datastore['AutoVerifySessionTimeout'].to_i)
        print_error("Meterpreter session #{session.sid} is not valid and will be closed")
        valid = false
      end
    end

    if valid

      if datastore['AutoLoadStdapi']

        session.load_stdapi

        if datastore['AutoSystemInfo']
          session.load_session_info
        end

        # only load priv on native windows
        if session.platform == 'windows' && [ARCH_X86, ARCH_X64].include?(session.arch)
          session.load_priv rescue nil
        end
      end

      if session.platform == 'android'
        session.load_android
      end

      [ 'InitialAutoRunScript', 'AutoRunScript' ].each do |key|
        if !datastore[key].empty?
          args = Shellwords.shellwords( datastore[key] )
          print_status("Session ID #{session.sid} (#{session.tunnel_to_s}) processing #{key} '#{datastore[key]}'")
          session.execute_script(args.shift, *args)
        end
      end
    end

    # Terminate the session without cleanup if it did not validate
    if not valid
      session.skip_cleanup = true
      session.kill
    end

    }

  end

end
end
end

