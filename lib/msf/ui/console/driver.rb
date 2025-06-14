# -*- coding: binary -*-
require 'find'
require 'erb'
require 'rexml/document'
require 'fileutils'
require 'digest/md5'

module Msf
module Ui
module Console

#
# A user interface driver on a console interface.
#
class Driver < Msf::Ui::Driver

  ConfigCore  = "framework/core"
  ConfigGroup = "framework/ui/console"

  DefaultPrompt     = "%undmsf#{Metasploit::Framework::Version::MAJOR}%clr"
  DefaultPromptChar = "%clr>"

  #
  # Console Command Dispatchers to be loaded after the Core dispatcher.
  #
  CommandDispatchers = [
    CommandDispatcher::Modules,
    CommandDispatcher::Jobs,
    CommandDispatcher::Resource,
    CommandDispatcher::Db,
    CommandDispatcher::Creds,
    CommandDispatcher::Developer,
    CommandDispatcher::DNS
  ]

  #
  # The console driver processes various framework notified events.
  #
  include FrameworkEventManager

  #
  # The console driver is a command shell.
  #
  include Rex::Ui::Text::DispatcherShell

  include Rex::Ui::Text::Resource

  #
  # Initializes a console driver instance with the supplied prompt string and
  # prompt character.  The optional hash can take extra values that will
  # serve to initialize the console driver.
  #
  # @option opts [Boolean] 'AllowCommandPassthru' (true) Whether to allow
  #   unrecognized commands to be executed by the system shell
  # @option opts [Boolean] 'Readline' (true) Whether to use the readline or not
  # @option opts [String] 'HistFile' (Msf::Config.history_file) Path to a file
  #   where we can store command history
  # @option opts [Array<String>] 'Resources' ([]) A list of resource files to
  #   load. If no resources are given, will load the default resource script,
  #   'msfconsole.rc' in the user's {Msf::Config.config_directory config
  #   directory}
  # @option opts [Boolean] 'SkipDatabaseInit' (false) Whether to skip
  #   connecting to the database and running migrations
  def initialize(prompt = DefaultPrompt, prompt_char = DefaultPromptChar, opts = {})
    setup_readline

    histfile = opts['HistFile'] || Msf::Config.history_file

    begin
      FeatureManager.instance.load_config
    rescue StandardError => e
      elog(e)
    end

    if opts['DeferModuleLoads'].nil?
      opts['DeferModuleLoads'] = Msf::FeatureManager.instance.enabled?(Msf::FeatureManager::DEFER_MODULE_LOADS)
    end

    # Initialize attributes

    framework_create_options = opts.merge({ 'DeferModuleLoads' => true })

    if Msf::FeatureManager.instance.enabled?(Msf::FeatureManager::DNS)
      dns_resolver = Rex::Proto::DNS::CachedResolver.new
      dns_resolver.extend(Rex::Proto::DNS::CustomNameserverProvider)
      dns_resolver.load_config if dns_resolver.has_config?

      # Defer loading of modules until paths from opts can be added below
      framework_create_options = framework_create_options.merge({ 'CustomDnsResolver' => dns_resolver })
    end
    self.framework = opts['Framework'] || Msf::Simple::Framework.create(framework_create_options)

    if self.framework.datastore['Prompt']
      prompt = self.framework.datastore['Prompt']
      prompt_char = self.framework.datastore['PromptChar'] || DefaultPromptChar
    end

    # Call the parent
    super(prompt, prompt_char, histfile, framework, :msfconsole)

    # Temporarily disable output
    self.disable_output = true

    # Load pre-configuration
    load_preconfig

    # Initialize the user interface to use a different input and output
    # handle if one is supplied
    input = opts['LocalInput']
    input ||= Rex::Ui::Text::Input::Stdio.new

    if !opts['Readline']
      input.disable_readline
    end

    if (opts['LocalOutput'])
      if (opts['LocalOutput'].kind_of?(String))
        output = Rex::Ui::Text::Output::File.new(opts['LocalOutput'])
      else
        output = opts['LocalOutput']
      end
    else
      output = Rex::Ui::Text::Output::Stdio.new
    end

    init_ui(input, output)
    init_tab_complete

    # Add the core command dispatcher as the root of the dispatcher
    # stack
    enstack_dispatcher(CommandDispatcher::Core)

    # Load the other "core" command dispatchers
    CommandDispatchers.each do |dispatcher_class|
      dispatcher = enstack_dispatcher(dispatcher_class)
      dispatcher.load_config(opts['Config'])
    end

    if !framework.db || !framework.db.active
      if framework.db.error == "disabled"
        print_warning("Database support has been disabled")
      else
        error_msg = "#{framework.db.error.class.is_a?(String) ? "#{framework.db.error.class} " : nil}#{framework.db.error}"
        print_warning("No database support: #{error_msg}")
      end
    end

    # Register event handlers
    register_event_handlers

    # Re-enable output
    self.disable_output = false

    # Whether or not command passthru should be allowed
    self.command_passthru = opts.fetch('AllowCommandPassthru', true)

    # Whether or not to confirm before exiting
    self.confirm_exit = opts['ConfirmExit']

    # Initialize the module paths only if we didn't get passed a Framework instance and 'DeferModuleLoads' is false
    unless opts['Framework']
      # Configure the framework module paths
      self.framework.init_module_paths(module_paths: opts['ModulePath'], defer_module_loads: opts['DeferModuleLoads'])
    end

    unless opts['DeferModuleLoads']
      framework.threads.spawn("ModuleCacheRebuild", true) do
        framework.modules.refresh_cache_from_module_files
      end
    end

    # Load console-specific configuration (after module paths are added)
    load_config(opts['Config'])

    # Process things before we actually display the prompt and get rocking
    on_startup(opts)

    # Process any resource scripts
    if opts['Resource'].blank?
      # None given, load the default
      default_resource = ::File.join(Msf::Config.config_directory, 'msfconsole.rc')
      load_resource(default_resource) if ::File.exist?(default_resource)
    else
      opts['Resource'].each { |r|
        load_resource(r)
      }
    end

    # Process persistent job handler
    begin
      restore_handlers = JSON.parse(File.read(Msf::Config.persist_file))
    rescue Errno::ENOENT, JSON::ParserError
      restore_handlers = nil
    end

    if restore_handlers
      print_status("Starting persistent handler(s)...")

      restore_handlers.each.with_index do |handler_opts, index|
        handler = framework.modules.create(handler_opts['mod_name'])
        handler.init_ui(self.input, self.output)
        replicant_handler = nil
        handler.exploit_simple(handler_opts['mod_options']) do |yielded_replicant_handler|
          replicant_handler = yielded_replicant_handler
        end

        if replicant_handler.nil? || replicant_handler.error
          print_status("Failed to start persistent payload handler ##{index} (#{handler_opts['mod_name']})")
          next
        end

        if replicant_handler.error.nil?
          job_id = handler.job_id
          print_status "Persistent payload handler started as Job #{job_id}"
        end
      end
    end

    # Process any additional startup commands
    if opts['XCommands'] and opts['XCommands'].kind_of? Array
      opts['XCommands'].each { |c|
        run_single(c)
      }
    end
  end

  #
  # Loads configuration that needs to be analyzed before the framework
  # instance is created.
  #
  def load_preconfig
    begin
      conf = Msf::Config.load
    rescue
      wlog("Failed to load configuration: #{$!}")
      return
    end

    if (conf.group?(ConfigCore))
      conf[ConfigCore].each_pair { |k, v|
        on_variable_set(true, k, v)
      }
    end
  end

  #
  # Loads configuration for the console.
  #
  def load_config(path=nil)
    begin
      conf = Msf::Config.load(path)
    rescue
      wlog("Failed to load configuration: #{$!}")
      return
    end

    # If we have configuration, process it
    if (conf.group?(ConfigGroup))
      conf[ConfigGroup].each_pair { |k, v|
        case k.downcase
          when 'activemodule'
            run_single("use #{v}")
          when 'activeworkspace'
            if framework.db.active
              workspace = framework.db.find_workspace(v)
              framework.db.workspace = workspace if workspace
            end
        end
      }
    end
  end

  #
  # Generate configuration for the console.
  #
  def get_config
    # Build out the console config group
    group = {}

    if (active_module)
      group['ActiveModule'] = active_module.fullname
    end

    if framework.db.active
      unless framework.db.workspace.default?
        group['ActiveWorkspace'] = framework.db.workspace.name
      end
    end

    group
  end

  def get_config_core
    ConfigCore
  end

  def get_config_group
    ConfigGroup
  end

  #
  # Saves configuration for the console.
  #
  def save_config
    begin
      Msf::Config.save(ConfigGroup => get_config)
    rescue ::Exception
      print_error("Failed to save console config: #{$!}")
    end
  end

  #
  # Saves the recent history to the specified file
  #
  def save_recent_history(path)
    num = Readline::HISTORY.length - hist_last_saved - 1

    tmprc = ""
    num.times { |x|
      tmprc << Readline::HISTORY[hist_last_saved + x] + "\n"
    }

    if tmprc.length > 0
      print_status("Saving last #{num} commands to #{path} ...")
      save_resource(tmprc, path)
    else
      print_error("No commands to save!")
    end

    # Always update this, even if we didn't save anything. We do this
    # so that we don't end up saving the "makerc" command itself.
    self.hist_last_saved = Readline::HISTORY.length
  end

  #
  # Creates the resource script file for the console.
  #
  def save_resource(data, path=nil)
    path ||= File.join(Msf::Config.config_directory, 'msfconsole.rc')

    begin
      rcfd = File.open(path, 'w')
      rcfd.write(data)
      rcfd.close
    rescue ::Exception
    end
  end

  #
  # Called before things actually get rolling such that banners can be
  # displayed, scripts can be processed, and other fun can be had.
  #
  def on_startup(opts = {})
    # Check for modules that failed to load
    if framework.modules.module_load_error_by_path.length > 0
      wlog("The following modules could not be loaded!")

      framework.modules.module_load_error_by_path.each do |path, _error|
        wlog("\t#{path}")
      end
    end

    if framework.modules.module_load_warnings.length > 0
      print_warning("The following modules were loaded with warnings:")

      framework.modules.module_load_warnings.each do |path, _error|
        wlog("\t#{path}")
      end
    end

    if framework.db&.active
      framework.db.workspace = framework.db.default_workspace unless framework.db.workspace
    end

    framework.events.on_ui_start(Msf::Framework::Revision)

    if $msf_spinner_thread
      $msf_spinner_thread.kill
      $stderr.print "\r" + (" " * 50) + "\n"
    end

    run_single("banner") unless opts['DisableBanner']

    payloads_manifest_errors = []
    begin
      payloads_manifest_errors = ::MetasploitPayloads.manifest_errors if framework.features.enabled?(::Msf::FeatureManager::METASPLOIT_PAYLOAD_WARNINGS)
    rescue ::StandardError => e
      $stderr.print('Could not verify the integrity of the Metasploit Payloads manifest')
      elog(e)
    end

    av_warning_message if (framework.eicar_corrupted? || payloads_manifest_errors.any?)

    if framework.features.enabled?(::Msf::FeatureManager::METASPLOIT_PAYLOAD_WARNINGS)
      if payloads_manifest_errors.any?
        warn_msg = "Metasploit Payloads manifest errors:\n"
        payloads_manifest_errors.each do |file|
          warn_msg << "\t#{file[:path]} : #{file[:error]}\n"
        end
        $stderr.print(warn_msg)
      end
    end

    opts["Plugins"].each do |plug|
      run_single("load '#{plug}'")
    end if opts["Plugins"]

    self.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
  end

  def av_warning_message
      avdwarn = "\e[31m"\
                "Warning: This copy of the Metasploit Framework has been corrupted by an installed anti-virus program."\
                " We recommend that you disable your anti-virus or exclude your Metasploit installation path, "\
                "then restore the removed files from quarantine or reinstall the framework.\e[0m"\
                "\n\n"

      $stderr.puts(Rex::Text.wordwrap(avdwarn, 0, 80))
  end

  #
  # Called when a variable is set to a specific value.  This allows the
  # console to do extra processing, such as enabling logging or doing
  # some other kind of task.  If this routine returns false it will indicate
  # that the variable is not being set to a valid value.
  #
  def on_variable_set(glob, var, val)
    case var.downcase
    when 'sessionlogging'
      handle_session_logging(val) if glob
    when 'sessiontlvlogging'
      handle_session_tlv_logging(val) if glob
    when 'consolelogging'
      handle_console_logging(val) if glob
    when 'loglevel'
      handle_loglevel(val) if glob
    when 'payload'
      handle_payload(val)
    when 'ssh_ident'
      handle_ssh_ident(val)
    end
  end

  #
  # Called when a variable is unset.  If this routine returns false it is an
  # indication that the variable should not be allowed to be unset.
  #
  def on_variable_unset(glob, var)
    case var.downcase
    when 'sessionlogging'
      handle_session_logging('0') if glob
    when 'sessiontlvlogging'
      handle_session_tlv_logging('false') if glob
    when 'consolelogging'
      handle_console_logging('0') if glob
    when 'loglevel'
      handle_loglevel(nil) if glob
    end
  end

  #
  # Proxies to shell.rb's update prompt with our own extras
  #
  def update_prompt(*args)
    if args.empty?
      pchar = framework.datastore['PromptChar'] || DefaultPromptChar
      p = framework.datastore['Prompt'] || DefaultPrompt
      p = "#{p} #{active_module.type}(%bld%red#{active_module.promptname}%clr)" if active_module
      super(p, pchar)
    else
      # Don't squash calls from within lib/rex/ui/text/shell.rb
      super(*args)
    end
  end

  #
  # The framework instance associated with this driver.
  #
  attr_reader   :framework
  #
  # Whether or not to confirm before exiting
  #
  attr_reader   :confirm_exit
  #
  # Whether or not commands can be passed through.
  #
  attr_reader   :command_passthru
  #
  # The active module associated with the driver.
  #
  attr_accessor :active_module
  #
  # The active session associated with the driver.
  #
  attr_accessor :active_session

  def stop
    framework.events.on_ui_stop()
    super
  end

protected

  attr_writer   :framework # :nodoc:
  attr_writer   :confirm_exit # :nodoc:
  attr_writer   :command_passthru # :nodoc:

  #
  # If an unknown command was passed, try to see if it's a valid local
  # executable.  This is only allowed if command passthru has been permitted
  #
  def unknown_command(method, line)
    if File.basename(method) == 'msfconsole'
      print_error('msfconsole cannot be run inside msfconsole')
      return
    end

    [method, method+".exe"].each do |cmd|
      if command_passthru && Rex::FileUtils.find_full_path(cmd)

        self.busy = true
        begin
          run_unknown_command(line)
        rescue ::Errno::EACCES, ::Errno::ENOENT
          print_error("Permission denied exec: #{line}")
        end
        self.busy = false
        return
      end
    end

    if framework.modules.create(method)
      super
      if prompt_yesno "This is a module we can load. Do you want to use #{method}?"
        run_single "use #{method}"
      end

      return
    end

    super
  end

  def run_unknown_command(command)
    print_status("exec: #{command}")
    print_line('')
    system(command)
  end

  ##
  #
  # Handlers for various global configuration values
  #
  ##

  #
  # SessionLogging.
  #
  def handle_session_logging(val)
    if (val =~ /^(y|t|1)/i)
      Msf::Logging.enable_session_logging(true)
      framework.sessions.values.each do |session|
        Msf::Logging.start_session_log(session)
      end
      print_line("Session logging enabled.")
    else
      Msf::Logging.enable_session_logging(false)
      framework.sessions.values.each do |session|
        Msf::Logging.stop_session_log(session)
      end
      print_line("Session logging disabled.")
    end
  end

  #
  # ConsoleLogging.
  #
  def handle_console_logging(val)
    if (val =~ /^(y|t|1)/i)
      Msf::Logging.enable_log_source('console')
      print_line("Console logging is now enabled.")

      set_log_source('console')

      rlog("\n[*] Console logging started: #{Time.now}\n\n", 'console')
    else
      rlog("\n[*] Console logging stopped: #{Time.now}\n\n", 'console')

      unset_log_source

      Msf::Logging.disable_log_source('console')
      print_line("Console logging is now disabled.")
    end
  end

  #
  # This method handles adjusting the global log level threshold.
  #
  def handle_loglevel(val)
    set_log_level(Rex::LogSource, val)
    set_log_level(Msf::LogSource, val)
  end

  #
  # This method handles setting a desired payload
  #
  # TODO: Move this out of the console driver!
  #
  def handle_payload(val)
    if framework && !framework.payloads.valid?(val)
      return false
    elsif active_module && (active_module.exploit? || active_module.evasion?)
      return false unless active_module.is_payload_compatible?(val)
    end
  end

  #
  # This method monkeypatches Net::SSH's client identification string
  #
  # TODO: Move this out of the console driver!
  #
  def handle_ssh_ident(val)
    # HACK: Suppress already initialized constant warning
    verbose, $VERBOSE = $VERBOSE, nil

    return false unless val.is_a?(String) && !val.empty?

    require 'net/ssh'

    # HACK: Bypass dynamic constant assignment error
    ::Net::SSH::Transport::ServerVersion.const_set(:PROTO_VERSION, val)

    true
  rescue LoadError
    print_error('Net::SSH could not be loaded')
    false
  rescue NameError
    print_error('Invalid constant Net::SSH::Transport::ServerVersion::PROTO_VERSION')
    false
  ensure
    # Restore warning
    $VERBOSE = verbose
  end

  def handle_session_tlv_logging(val)
    return false if val.nil?

    if val.casecmp?('console') || val.casecmp?('true') || val.casecmp?('false')
      return true
    elsif val.start_with?('file:') && !val.split('file:').empty?
      pathname = ::Pathname.new(val.split('file:').last)

      # Check if we want to write the log to file
      if ::File.file?(pathname)
        if ::File.writable?(pathname)
          return true
        else
          print_status "No write permissions for log output file: #{pathname}"
          return false
        end
        # Check if we want to write the log file to a directory
      elsif ::File.directory?(pathname)
        if ::File.writable?(pathname)
          return true
        else
          print_status "No write permissions for log output directory: #{pathname}"
          return false
        end
        # Check if the subdirectory exists
      elsif ::File.directory?(pathname.dirname)
        if ::File.writable?(pathname.dirname)
          return true
        else
          print_status "No write permissions for log output directory: #{pathname.dirname}"
          return false
        end
      else
        # Else the directory doesn't exist. Check if we can create it.
        begin
          ::FileUtils.mkdir_p(pathname.dirname)
          return true
        rescue ::StandardError => e
          print_status "Error when trying to create directory #{pathname.dirname}: #{e.message}"
          return false
        end
      end
    end

    false
  end

  # Require the appropriate readline library based on the user's preference.
  #
  # @return [void]
  def setup_readline
    require 'readline'

    # Only Windows requires a monkey-patched RbReadline
    return unless Rex::Compat.is_windows

    if defined?(::RbReadline) && !defined?(RbReadline.refresh_console_handle)
      ::RbReadline.instance_eval do
        class << self
          alias_method :old_rl_move_cursor_relative, :_rl_move_cursor_relative
          alias_method :old_rl_get_screen_size, :_rl_get_screen_size
          alias_method :old_space_to_eol, :space_to_eol
          alias_method :old_insert_some_chars, :insert_some_chars
        end

        def self.refresh_console_handle
          # hConsoleHandle gets set only when RbReadline detects it is running on Windows.
          # Therefore, we don't need to check Rex::Compat.is_windows, we can simply check if hConsoleHandle is nil or not.
          @hConsoleHandle = @GetStdHandle.Call(::Readline::STD_OUTPUT_HANDLE) if @hConsoleHandle
        end

        def self._rl_move_cursor_relative(*args)
          refresh_console_handle
          old_rl_move_cursor_relative(*args)
        end

        def self._rl_get_screen_size(*args)
          refresh_console_handle
          old_rl_get_screen_size(*args)
        end

        def self.space_to_eol(*args)
          refresh_console_handle
          old_space_to_eol(*args)
        end

        def self.insert_some_chars(*args)
          refresh_console_handle
          old_insert_some_chars(*args)
        end
      end
    end
  end
end

end
end
end
