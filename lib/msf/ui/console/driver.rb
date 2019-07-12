# -*- coding: binary -*-
require 'msf/core'
require 'msf/base'
require 'msf/ui'
require 'msf/ui/console/framework_event_manager'
require 'msf/ui/console/command_dispatcher'
require 'msf/ui/console/table'
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

  DefaultPrompt     = "%undmsf%clr"
  DefaultPromptChar = "%clr>"

  #
  # Console Command Dispatchers to be loaded after the Core dispatcher.
  #
  CommandDispatchers = [
    CommandDispatcher::Modules,
    CommandDispatcher::Jobs,
    CommandDispatcher::Resource,
    CommandDispatcher::Developer
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
  # @option opts [Boolean] 'RealReadline' (false) Whether to use the system's
  #   readline library instead of RBReadline
  # @option opts [String] 'HistFile' (Msf::Config.history_file) Path to a file
  #   where we can store command history
  # @option opts [Array<String>] 'Resources' ([]) A list of resource files to
  #   load. If no resources are given, will load the default resource script,
  #   'msfconsole.rc' in the user's {Msf::Config.config_directory config
  #   directory}
  # @option opts [Boolean] 'SkipDatabaseInit' (false) Whether to skip
  #   connecting to the database and running migrations
  def initialize(prompt = DefaultPrompt, prompt_char = DefaultPromptChar, opts = {})
    choose_readline(opts)

    histfile = opts['HistFile'] || Msf::Config.history_file

    # Initialize attributes

    # Defer loading of modules until paths from opts can be added below
    framework_create_options = opts.merge('DeferModuleLoads' => true)
    self.framework = opts['Framework'] || Msf::Simple::Framework.create(framework_create_options)

    if self.framework.datastore['Prompt']
      prompt = self.framework.datastore['Prompt']
      prompt_char = self.framework.datastore['PromptChar'] || DefaultPromptChar
    end

    # Call the parent
    super(prompt, prompt_char, histfile, framework)

    # Temporarily disable output
    self.disable_output = true

    # Load pre-configuration
    load_preconfig

    # Initialize the user interface to use a different input and output
    # handle if one is supplied
    input = opts['LocalInput']
    input ||= Rex::Ui::Text::Input::Stdio.new

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

    # Report readline error if there was one..
    if !@rl_err.nil?
      print_error("***")
      print_error("* WARNING: Unable to load readline: #{@rl_err}")
      print_error("* Falling back to RbReadLine")
      print_error("***")
    end

    # Load the other "core" command dispatchers
    CommandDispatchers.each do |dispatcher|
      enstack_dispatcher(dispatcher)
    end

    # Add the database dispatcher if it is usable
    if (framework.db.usable)
      require 'msf/ui/console/command_dispatcher/db'
      enstack_dispatcher(CommandDispatcher::Db)
      require 'msf/ui/console/command_dispatcher/creds'
      enstack_dispatcher(CommandDispatcher::Creds)
    else
      print_error("***")
      if framework.db.error == "disabled"
        print_error("* WARNING: Database support has been disabled")
      else
        print_error("* WARNING: No database support: #{framework.db.error.class} #{framework.db.error}")
      end
      print_error("***")
    end

    # Register event handlers
    register_event_handlers

    # Re-enable output
    self.disable_output = false

    # Whether or not command passthru should be allowed
    self.command_passthru = opts.fetch('AllowCommandPassthru', true)

    # Whether or not to confirm before exiting
    self.confirm_exit = opts['ConfirmExit']

    # Parse any specified database.yml file
    if framework.db.usable and not opts['SkipDatabaseInit']

      # Append any migration paths necessary to bring the database online
      if opts['DatabaseMigrationPaths']
        opts['DatabaseMigrationPaths'].each do |migrations_path|
          ActiveRecord::Migrator.migrations_paths << migrations_path
        end
      end

      if framework.db.connection_established?
        framework.db.after_establish_connection
      else
        configuration_pathname = Metasploit::Framework::Database.configurations_pathname(path: opts['DatabaseYAML'])

        unless configuration_pathname.nil?
          if configuration_pathname.readable?
            dbinfo = YAML.load_file(configuration_pathname) || {}
            dbenv  = opts['DatabaseEnv'] || Rails.env
            db     = dbinfo[dbenv]
          else
            print_error("Warning, #{configuration_pathname} is not readable. Try running as root or chmod.")
          end

          if not db
            print_error("No database definition for environment #{dbenv}")
          else
            framework.db.connect(db)
          end
        end
      end

      # framework.db.active will be true if after_establish_connection ran
      # directly when connection_established? was already true or if
      # framework.db.connect called after_establish_connection.
      if !!framework.db.error
        print_error("Failed to connect to the database: #{framework.db.error}")
      end
    end

    # Initialize the module paths only if we didn't get passed a Framework instance and 'DeferModuleLoads' is false
    unless opts['Framework'] || opts['DeferModuleLoads']
      # Configure the framework module paths
      self.framework.init_module_paths(module_paths: opts['ModulePath'])
    end

    if !opts['DeferModuleLoads']
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

      restore_handlers.each do |handler_opts|
        handler = framework.modules.create(handler_opts['mod_name'])
        handler.exploit_simple(handler_opts['mod_options'])
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
  # Saves configuration for the console.
  #
  def save_config
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

    # Save it
    begin
      Msf::Config.save(ConfigGroup => group)
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
      print_error("WARNING! The following modules could not be loaded!")

      framework.modules.module_load_error_by_path.each do |path, error|
        print_error("\t#{path}: #{error}")
      end
    end

    if framework.modules.module_load_warnings.length > 0
      print_warning("The following modules were loaded with warnings:")
      framework.modules.module_load_warnings.each do |path, error|
        print_warning("\t#{path}: #{error}")
      end
    end

    framework.events.on_ui_start(Msf::Framework::Revision)

    if $msf_spinner_thread
      $msf_spinner_thread.kill
      $stderr.print "\r" + (" " * 50) + "\n"
    end

    run_single("banner") unless opts['DisableBanner']

    opts["Plugins"].each do |plug|
      run_single("load '#{plug}'")
    end if opts["Plugins"]

    self.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
  end

  #
  # Called when a variable is set to a specific value.  This allows the
  # console to do extra processing, such as enabling logging or doing
  # some other kind of task.  If this routine returns false it will indicate
  # that the variable is not being set to a valid value.
  #
  def on_variable_set(glob, var, val)
    case var.downcase
    when 'payload'
      if framework && !framework.payloads.valid?(val)
        return false
      elsif active_module && active_module.type == 'exploit' && !active_module.is_payload_compatible?(val)
        return false
      elsif active_module
        active_module.datastore.clear_non_user_defined
      elsif framework
        framework.datastore.clear_non_user_defined
      end
    when 'sessionlogging'
      handle_session_logging(val) if glob
    when 'consolelogging'
      handle_console_logging(val) if glob
    when 'loglevel'
      handle_loglevel(val) if glob
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

        print_status("exec: #{line}")
        print_line('')

        self.busy = true
        begin
          system(line)
        rescue ::Errno::EACCES, ::Errno::ENOENT
          print_error("Permission denied exec: #{line}")
        end
        self.busy = false
        return
      elsif framework.modules.create(method)
        super
        if prompt_yesno "This is a module we can load. Do you want to use #{method}?"
          run_single "use #{method}"
        end

        return
      end
    end

    super
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
      print_line("Session logging will be enabled for future sessions.")
    else
      Msf::Logging.enable_session_logging(false)
      print_line("Session logging will be disabled for future sessions.")
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

  # Require the appropriate readline library based on the user's preference.
  #
  # @return [void]
  def choose_readline(opts)
    # Choose a readline library before calling the parent
    @rl_err = nil
    if opts['RealReadline']
      # Remove the gem version from load path to be sure we're getting the
      # stdlib readline.
      gem_dir = Gem::Specification.find_all_by_name('rb-readline').first.gem_dir
      rb_readline_path = File.join(gem_dir, "lib")
      index = $LOAD_PATH.index(rb_readline_path)
      # Bundler guarantees that the gem will be there, so it should be safe to
      # assume we found it in the load path, but check to be on the safe side.
      if index
        $LOAD_PATH.delete_at(index)
      end
    end

    begin
      require 'readline'
    rescue ::LoadError => e
      if @rl_err.nil? && index
        # Then this is the first time the require failed and we have an index
        # for the gem version as a fallback.
        @rl_err = e
        # Put the gem back and see if that works
        $LOAD_PATH.insert(index, rb_readline_path)
        index = rb_readline_path = nil
        retry
      else
        # Either we didn't have the gem to fall back on, or we failed twice.
        # Nothing more we can do here.
        raise e
      end
    end
  end
end

end
end
end
