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
				OptString.new('InitialAutoRunScript', [false, "An initial script to run on session creation (before AutoRunScript)", '']),
				OptString.new('AutoRunScript', [false, "A script to run automatically on session creation.", '']),
				OptBool.new('AutoSystemInfo', [true, "Automatically capture system information on initialization.", true]),
				OptBool.new('EnableUnicodeEncoding', [true, "Automatically encode UTF-8 strings as hexadecimal", true]),
				OptEnum.new('TransportSSLVersion', [false, "Use SSLv3 or TLSv1 for meterpreter session", 'SSLv3', %w(TLSv1 SSLv3)])
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
    session.encode_unicode = ( datastore['EnableUnicodeEncoding'] ? true : false )

    session.init_ui(self.user_input, self.user_output)

    if (datastore['AutoLoadStdapi'] == true)

      session.load_stdapi

      if datastore['AutoSystemInfo']
        session.load_session_info
      end

=begin
      admin = false
      begin
        ::Timeout.timeout(30) do
          if session.railgun and session.railgun.shell32.IsUserAnAdmin()["return"] == true
            admin = true
            session.info += " (ADMIN)"
          end
        end
      rescue ::Exception
      end
=end
      if session.platform =~ /win32|win64/i
        session.load_priv rescue nil
      end
    end

    [ 'InitialAutoRunScript', 'AutoRunScript' ].each do |key|
      if (datastore[key].empty? == false)
        args = Shellwords.shellwords( datastore[key] )
        print_status("Session ID #{session.sid} (#{session.tunnel_to_s}) processing #{key} '#{datastore[key]}'")
        session.execute_script(args.shift, *args)
      end
    end

    }

  end

end
end
end

