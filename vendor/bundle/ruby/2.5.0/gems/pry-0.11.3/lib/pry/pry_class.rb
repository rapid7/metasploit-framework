require 'pry/config'
class Pry

  HOME_RC_FILE = ENV["PRYRC"] || "~/.pryrc"
  LOCAL_RC_FILE = "./.pryrc"

  class << self
    extend Pry::Forwardable
    attr_accessor :custom_completions
    attr_accessor :current_line
    attr_accessor :line_buffer
    attr_accessor :eval_path
    attr_accessor :cli
    attr_accessor :quiet
    attr_accessor :last_internal_error
    attr_accessor :config
    attr_writer :history

    def_delegators :@plugin_manager, :plugins, :load_plugins, :locate_plugins

    extend Pry::Config::Convenience
    config_shortcut(*Pry::Config.shortcuts)

    def prompt=(value)
      config.prompt = value
    end

    def prompt
      config.prompt
    end

    def history
      @history ||= History.new
    end

    #
    # @example
    #  Pry.configure do |config|
    #     config.eager_load! # optional
    #     config.input =     # ..
    #     config.foo = 2
    #  end
    #
    # @yield [config]
    #   Yields a block with {Pry.config} as its argument.
    #
    def configure
      yield config
    end
  end

  #
  # @return [main]
  #   returns the special instance of Object, "main".
  #
  def self.main
    @main ||= TOPLEVEL_BINDING.eval "self"
  end

  #
  # @return [Pry::Config]
  #  Returns a value store for an instance of Pry running on the current thread.
  #
  def self.current
    Thread.current[:__pry__] ||= Pry::Config.from_hash({}, nil)
  end

  # Load the given file in the context of `Pry.toplevel_binding`
  # @param [String] file The unexpanded file path.
  def self.load_file_at_toplevel(file)
    toplevel_binding.eval(File.read(file), file)
  rescue RescuableException => e
    puts "Error loading #{file}: #{e}\n#{e.backtrace.first}"
  end

  # Load HOME_RC_FILE and LOCAL_RC_FILE if appropriate
  # This method can also be used to reload the files if they have changed.
  def self.load_rc_files
    rc_files_to_load.each do |file|
      critical_section do
        load_file_at_toplevel(file)
      end
    end
  end

  # Load the local RC file (./.pryrc)
  def self.rc_files_to_load
    files = []
    files << HOME_RC_FILE if Pry.config.should_load_rc
    files << LOCAL_RC_FILE if Pry.config.should_load_local_rc
    files.map { |file| real_path_to(file) }.compact.uniq
  end

  # Expand a file to its canonical name (following symlinks as appropriate)
  def self.real_path_to(file)
    expanded = Pathname.new(File.expand_path(file)).realpath.to_s
    # For rbx 1.9 mode [see rubinius issue #2165]
    File.exist?(expanded) ? expanded : nil
  rescue Errno::ENOENT, Errno::EACCES
    nil
  end

  # Load any Ruby files specified with the -r flag on the command line.
  def self.load_requires
    Pry.config.requires.each do |file|
      require file
    end
  end

  # Trap interrupts on jruby, and make them behave like MRI so we can
  # catch them.
  def self.load_traps
    trap('INT'){ raise Interrupt }
  end

  def self.load_win32console
    begin
      require 'win32console'
      # The mswin and mingw versions of pry require win32console, so this should
      # only fail on jruby (where win32console doesn't work).
      # Instead we'll recommend ansicon, which does.
    rescue LoadError
      warn <<-WARNING if Pry.config.windows_console_warning
For a better Pry experience on Windows, please use ansicon:
  https://github.com/adoxa/ansicon
If you use an alternative to ansicon and don't want to see this warning again,
you can add "Pry.config.windows_console_warning = false" to your .pryrc.
      WARNING
    end
  end

  # Do basic setup for initial session.
  # Including: loading .pryrc, loading plugins, loading requires, and
  # loading history.
  def self.initial_session_setup
    return unless initial_session?
    @initial_session = false

    # note these have to be loaded here rather than in pry_instance as
    # we only want them loaded once per entire Pry lifetime.
    load_rc_files
  end

  def self.final_session_setup
    return if @session_finalized
    @session_finalized = true
    load_plugins if Pry.config.should_load_plugins
    load_requires if Pry.config.should_load_requires
    load_history if Pry.config.history.should_load
    load_traps if Pry.config.should_trap_interrupts
    load_win32console if Pry::Helpers::BaseHelpers.windows? && !Pry::Helpers::BaseHelpers.windows_ansi?
  end

  # Start a Pry REPL.
  # This method also loads `~/.pryrc` and `./.pryrc` as necessary the
  # first time it is invoked.
  # @param [Object, Binding] target The receiver of the Pry session
  # @param [Hash] options
  # @option options (see Pry#initialize)
  # @example
  #   Pry.start(Object.new, :input => MyInput.new)
  def self.start(target=nil, options={})
    return if ENV['DISABLE_PRY']
    if ENV['FAIL_PRY']
      raise 'You have FAIL_PRY set to true, which results in Pry calls failing'
    end
    options = options.to_hash

    if in_critical_section?
      output.puts "ERROR: Pry started inside Pry."
      output.puts "This can happen if you have a binding.pry inside a #to_s or #inspect function."
      return
    end

    options[:target] = Pry.binding_for(target || toplevel_binding)
    initial_session_setup
    final_session_setup

    # Unless we were given a backtrace, save the current one
    if options[:backtrace].nil?
      options[:backtrace] = caller

      # If Pry was started via `binding.pry`, elide that from the backtrace
      if options[:backtrace].first =~ /pry.*core_extensions.*pry/
        options[:backtrace].shift
      end
    end

    driver = options[:driver] || Pry::REPL

    # Enter the matrix
    driver.start(options)
  rescue Pry::TooSafeException
    puts "ERROR: Pry cannot work with $SAFE > 0"
    raise
  end

  # Execute the file through the REPL loop, non-interactively.
  # @param [String] file_name File name to load through the REPL.
  def self.load_file_through_repl(file_name)
    require "pry/repl_file_loader"
    REPLFileLoader.new(file_name).load
  end

  #
  # An inspector that clips the output to `max_length` chars.
  # In case of > `max_length` chars the `#<Object...> notation is used.
  #
  # @param [Object] obj
  #   The object to view.
  #
  # @param [Hash] options
  # @option options [Integer] :max_length (60)
  #   The maximum number of chars before clipping occurs.
  #
  # @option options [Boolean] :id (false)
  #   Boolean to indicate whether or not a hex reprsentation of the object ID
  #   is attached to the return value when the length of inspect is greater than
  #   value of `:max_length`.
  #
  # @return [String]
  #   The string representation of `obj`.
  #
  def self.view_clip(obj, options = {})
    max = options.fetch :max_length, 60
    id = options.fetch :id, false
    if obj.kind_of?(Module) && obj.name.to_s != "" && obj.name.to_s.length <= max
      obj.name.to_s
    elsif Pry.main == obj
      # special-case to support jruby.
      # fixed as of https://github.com/jruby/jruby/commit/d365ebd309cf9df3dde28f5eb36ea97056e0c039
      # we can drop in the future.
      obj.to_s
    elsif Pry.config.prompt_safe_objects.any? { |v| v === obj } && obj.inspect.length <= max
      obj.inspect
    else
      id == true ? "#<#{obj.class}:0x%x>" % (obj.object_id << 1) : "#<#{obj.class}>"
    end
  rescue RescuableException
    "unknown"
  end

  # Load Readline history if required.
  def self.load_history
    Pry.history.load
  end

  # @return [Boolean] Whether this is the first time a Pry session has
  #   been started since loading the Pry class.
  def self.initial_session?
    @initial_session
  end

  # Run a Pry command from outside a session. The commands available are
  # those referenced by `Pry.config.commands` (the default command set).
  # @param [String] command_string The Pry command (including arguments,
  #   if any).
  # @param [Hash] options Optional named parameters.
  # @return [nil]
  # @option options [Object, Binding] :target The object to run the
  #   command under. Defaults to `TOPLEVEL_BINDING` (main).
  # @option options [Boolean] :show_output Whether to show command
  #   output. Defaults to true.
  # @example Run at top-level with no output.
  #   Pry.run_command "ls"
  # @example Run under Pry class, returning only public methods.
  #   Pry.run_command "ls -m", :target => Pry
  # @example Display command output.
  #   Pry.run_command "ls -av", :show_output => true
  def self.run_command(command_string, options={})
    options = {
      :target => TOPLEVEL_BINDING,
      :show_output => true,
      :output => Pry.config.output,
      :commands => Pry.config.commands
    }.merge!(options)

    # :context for compatibility with <= 0.9.11.4
    target = options[:context] || options[:target]
    output = options[:show_output] ? options[:output] : StringIO.new

    pry = Pry.new(:output   => output, :target   => target, :commands => options[:commands])
    pry.eval command_string
    nil
  end

  def self.default_editor_for_platform
    return ENV['VISUAL'] if ENV['VISUAL'] and not ENV['VISUAL'].empty?
    return ENV['EDITOR'] if ENV['EDITOR'] and not ENV['EDITOR'].empty?
    if Helpers::BaseHelpers.windows?
      'notepad'
    else
      %w(editor nano vi).detect do |editor|
        system("which #{editor} > /dev/null 2>&1")
      end
    end
  end

  def self.auto_resize!
    Pry.config.input # by default, load Readline

    if !defined?(Readline) || Pry.config.input != Readline
      warn "Sorry, you must be using Readline for Pry.auto_resize! to work."
      return
    end

    if Readline::VERSION =~ /edit/i
      warn <<-EOT
Readline version #{Readline::VERSION} detected - will not auto_resize! correctly.
  For the fix, use GNU Readline instead:
  https://github.com/guard/guard/wiki/Add-proper-Readline-support-to-Ruby-on-Mac-OS-X
      EOT
      return
    end

    trap :WINCH do
      begin
        Readline.set_screen_size(*Terminal.size!)
      rescue => e
        warn "\nPry.auto_resize!'s Readline.set_screen_size failed: #{e}"
      end
      begin
        Readline.refresh_line
      rescue => e
        warn "\nPry.auto_resize!'s Readline.refresh_line failed: #{e}"
      end
    end
  end

  # Set all the configurable options back to their default values
  def self.reset_defaults
    @initial_session = true
    @session_finalized = nil

    self.config = Pry::Config.new Pry::Config::Default.new
    self.cli = false
    self.current_line = 1
    self.line_buffer = [""]
    self.eval_path = "(pry)"
  end

  # Basic initialization.
  def self.init
    @plugin_manager ||= PluginManager.new
    reset_defaults
    locate_plugins
  end

  # Return a `Binding` object for `target` or return `target` if it is
  # already a `Binding`.
  # In the case where `target` is top-level then return `TOPLEVEL_BINDING`
  # @param [Object] target The object to get a `Binding` object for.
  # @return [Binding] The `Binding` object.
  def self.binding_for(target)
    if Binding === target
      target
    else
      if Pry.main == target
        TOPLEVEL_BINDING
      else
        target.__binding__
      end
    end
  end

  def self.toplevel_binding
    unless defined?(@toplevel_binding) && @toplevel_binding
      # Grab a copy of the TOPLEVEL_BINDING without any local variables.
      # This binding has a default definee of Object, and new methods are
      # private (just as in TOPLEVEL_BINDING).
      TOPLEVEL_BINDING.eval <<-RUBY
        def self.__pry__
          binding
        end
        Pry.toplevel_binding = __pry__
        class << self; undef __pry__; end
      RUBY
    end
    @toplevel_binding.eval('private')
    @toplevel_binding
  end

  def self.toplevel_binding=(binding)
    @toplevel_binding = binding
  end

  def self.in_critical_section?
    Thread.current[:pry_critical_section] ||= 0
    Thread.current[:pry_critical_section] > 0
  end

  def self.critical_section(&block)
    Thread.current[:pry_critical_section] ||= 0
    Thread.current[:pry_critical_section] += 1
    yield
  ensure
    Thread.current[:pry_critical_section] -= 1
  end
end

Pry.init
