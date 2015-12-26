class Msf::SessionManager::Initializer
  include Celluloid

  # @param options [Hash{Symbol => Object}]
  # @option options [Boolean] :auto_load_android (false)
  # @option options [Boolean] :auto_load_stdapi (false)
  # @option options [String, nil] :auto_run_script (nil)
  # @option options [Boolean] :auto_system_info (false)
  # @option options [Boolean] :enable_unicode_encoding
  # @option options [String, nil] :initial_auto_run_script
  # @option options [Msf::Session] :session
  # @option options :user_input
  # @option options :user_output
  def start_session(options={})
    options.assert_valid_keys(
        :auto_load_android,
        :auto_load_stdapi,
        :auto_run_script,
        :auto_system_info,
        :enable_unicode_encoding,
        :initial_auto_run_script,
        :session,
        :user_input,
        :user_output
    )

    session = options.fetch(:session)

    # Configure unicode encoding before loading stdapi
    session.encode_unicode = options.fetch(:enable_unicode_encoding)

    session.init_ui(
        options.fetch(:user_input),
        options.fetch(:user_output)
    )

    if options.fetch(:auto_load_stdapi)
      session.load_stdapi

      if options.fetch(:auto_system_info)
        session.load_session_info
      end

      if session.platform =~ /win32|win64/i
        session.load_priv rescue nil
      end
    end

    if session.platform =~ /android/i && options.fetch(:auto_load_android)
      session.load_android
    end

    [:initial_auto_run_script, :auto_run_script].each do |key|
      value = options[key]

      if value.present?
        print_status("Session ID #{session.sid} (#{session.tunnel_to_s}) processing #{key} '#{value}'")
        split = Shellwords.shellwords(value)
        script_name = split[0]
        script_arguments = split[1..-1]
        session.execute_script(script_name, *script_arguments)
      end
    end
  end
end