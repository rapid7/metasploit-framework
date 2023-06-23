# -*- coding: binary -*-

class Msf::Ui::Console::CommandDispatcher::Developer

  include Msf::Ui::Console::CommandDispatcher

  @@irb_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help menu.'             ],
    '-e' => [true,  'Expression to evaluate.']
  )

  @@time_opts = Rex::Parser::Arguments.new(
    ['-h', '--help'] => [ false, 'Help banner.' ],
    '--cpu' => [false, 'Profile the CPU usage.'],
    '--memory' => [false,  'Profile the memory usage.']
  )

  @@_servicemanager_opts = Rex::Parser::Arguments.new(
    ['-l', '--list'] => [false, 'View the currently running services' ]
  )

  def initialize(driver)
    super
    @modified_files = modified_file_paths(print_errors: false)
  end

  def name
    'Developer'
  end

  def commands
    commands = {
      'irb'        => 'Open an interactive Ruby shell in the current context',
      'pry'        => 'Open the Pry debugger on the current module or Framework',
      'edit'       => 'Edit the current module or a file with the preferred editor',
      'reload_lib' => 'Reload Ruby library files from specified paths',
      'log'        => 'Display framework.log paged to the end if possible',
      'time'       => 'Time how long it takes to run a particular command'
    }
    if framework.features.enabled?(Msf::FeatureManager::SERVICEMANAGER_COMMAND)
      commands['_servicemanager'] = 'Interact with the Rex::ServiceManager'
    end
    commands
  end

  def local_editor
    framework.datastore['LocalEditor'] ||
    Rex::Compat.getenv('VISUAL')       ||
    Rex::Compat.getenv('EDITOR')       ||
    Msf::Util::Helper.which('vim')     ||
    Msf::Util::Helper.which('vi')
  end

  def local_pager
    framework.datastore['LocalPager'] ||
    Rex::Compat.getenv('PAGER')       ||
    Rex::Compat.getenv('MANPAGER')    ||
    Msf::Util::Helper.which('less')   ||
    Msf::Util::Helper.which('more')
  end

  # XXX: This will try to reload *any* .rb and break on modules
  def reload_file(path, print_errors: true)
    full_path = File.expand_path(path)

    unless File.exist?(full_path) && full_path.end_with?('.rb')
      print_error("#{full_path} must exist and be a .rb file") if print_errors
      return
    end

    # The file must exist to reach this, so we try our best here
    if full_path.start_with?(Msf::Config.module_directory, Msf::Config.user_module_directory)
      print_error('Reloading Metasploit modules is not supported (try "reload")') if print_errors
      return
    end

    print_status("Reloading #{full_path}")
    load full_path
  end

  # @return [Array<String>] The list of modified file paths since startup
  def modified_file_paths(print_errors: true)
    files, is_success = modified_files

    unless is_success
      print_error("Git is not available") if print_errors
      files = []
    end

    @modified_files ||= []
    @modified_files |= files.map do |file|
      next if file.end_with?('_spec.rb') || file.end_with?("spec_helper.rb")
      File.join(Msf::Config.install_root, file)
    end.compact
    @modified_files
  end

  def cmd_irb_help
    print_line 'Usage: irb'
    print_line
    print_line 'Open an interactive Ruby shell in the current context.'
    print @@irb_opts.usage
  end

  #
  # Open an interactive Ruby shell in the current context
  #
  def cmd_irb(*args)
    expressions = []

    # Parse the command options
    @@irb_opts.parse(args) do |opt, idx, val|
      case opt
      when '-e'
        expressions << val
      when '-h'
        cmd_irb_help
        return false
      end
    end

    if expressions.empty?
      print_status('Starting IRB shell...')

      Rex::Ui::Text::Shell::HistoryManager.with_context(name: :irb) do
        begin
          if active_module
            print_status("You are in #{active_module.fullname}\n")
            Rex::Ui::Text::IrbShell.new(active_module).run
          else
            print_status("You are in the \"framework\" object\n")
            Rex::Ui::Text::IrbShell.new(framework).run
          end
        rescue
          print_error("Error during IRB: #{$!}\n\n#{$@.join("\n")}")
        end
      end

      # Reset tab completion
      if (driver.input.supports_readline)
        driver.input.reset_tab_completion
      end
    else
      # XXX: No vprint_status here either
      if framework.datastore['VERBOSE'].to_s == 'true'
        print_status("You are executing expressions in #{binding.receiver}")
      end

      expressions.each { |expression| eval(expression, binding) }
    end
  end

  #
  # Tab completion for the irb command
  #
  def cmd_irb_tabs(_str, words)
    return [] if words.length > 1

    @@irb_opts.option_keys
  end

  def cmd_pry_help
    print_line 'Usage: pry'
    print_line
    print_line 'Open the Pry debugger on the current module or Framework.'
    print_line
  end

  #
  # Open the Pry debugger on the current module or Framework
  #
  def cmd_pry(*args)
    if args.include?('-h')
      cmd_pry_help
      return
    end

    begin
      require 'pry'
    rescue LoadError
      print_error('Failed to load Pry, try "gem install pry"')
      return
    end

    print_status('Starting Pry shell...')

    Pry.config.history_load = false
    Rex::Ui::Text::Shell::HistoryManager.with_context(history_file: Msf::Config.pry_history, name: :pry) do
      if active_module
        print_status("You are in the \"#{active_module.fullname}\" module object\n")
        active_module.pry
      else
        print_status("You are in the \"framework\" object\n")
        framework.pry
      end
    end
  end

  def cmd_edit_help
    print_line 'Usage: edit [file/to/edit]'
    print_line
    print_line "Edit the currently active module or a local file with #{local_editor}."
    print_line 'To change the preferred editor, you can "setg LocalEditor".'
    print_line 'If a library file is specified, it will automatically be reloaded after editing.'
    print_line 'Otherwise, you can reload the active module with "reload" or "rerun".'
    print_line
  end

  #
  # Edit the current module or a file with the preferred editor
  #
  def cmd_edit(*args)
    editing_module = false

    if args.length > 0
      path = File.expand_path(args[0])
    elsif active_module
      editing_module = true
      path = active_module.file_path
    end

    unless path
      print_error('Nothing to edit. Try using a module first or specifying a library file to edit.')
      return
    end

    editor = local_editor

    unless editor
      # ed(1) is the standard editor
      editor = 'ed'
      print_warning("LocalEditor or $VISUAL/$EDITOR should be set. Falling back on #{editor}.")
    end

    # XXX: No vprint_status in this context?
    # XXX: VERBOSE is a string instead of Bool??
    print_status("Launching #{editor} #{path}") if framework.datastore['VERBOSE'].to_s == 'true'

    unless system(*editor.split, path)
      print_error("Could not execute #{editor} #{path}")
      return
    end

    return if editing_module

    reload_file(path)
  end

  #
  # Tab completion for the edit command
  #
  def cmd_edit_tabs(str, words)
    tab_complete_filenames(str, words)
  end

  def cmd_reload_lib_help
    cmd_reload_lib('-h')
  end

  #
  # Reload Ruby library files from specified paths
  #
  def cmd_reload_lib(*args)
    files = []
    options = OptionParser.new do |opts|
      opts.banner = 'Usage: reload_lib lib/to/reload.rb [...]'
      opts.separator ''
      opts.separator 'Reload Ruby library files from specified paths.'
      opts.separator ''

      opts.on '-h', '--help', 'Help banner.' do
        return print(opts.help)
      end

      opts.on '-a', '--all', 'Reload all* changed files in your current Git working tree.
                                     *Excludes modules and non-Ruby files.' do
        files.concat(modified_file_paths)
      end
    end

    # The remaining unparsed arguments are files
    files.concat(options.order(args))
    files.uniq!

    return print(options.help) if files.empty?

    files.each do |file|
      reload_file(file)
    rescue ScriptError, StandardError => e
      print_error("Error while reloading file #{file.inspect}: #{e}:\n#{e.backtrace.to_a.map { |line| "  #{line}" }.join("\n")}")
    end
  end

  #
  # Tab completion for the reload_lib command
  #
  def cmd_reload_lib_tabs(str, words)
    tab_complete_filenames(str, words)
  end

  def cmd_log_help
    print_line 'Usage: log'
    print_line
    print_line 'Display framework.log paged to the end if possible.'
    print_line 'To change the preferred pager, you can "setg LocalPager".'
    print_line 'For full effect, "setg LogLevel 3" before running modules.'
    print_line
    print_line "Log location: #{File.join(Msf::Config.log_directory, 'framework.log')}"
    print_line
  end

  #
  # Display framework.log paged to the end if possible
  #
  def cmd_log(*args)
    path = File.join(Msf::Config.log_directory, 'framework.log')

    # XXX: +G isn't portable and may hang on large files
    pager = local_pager.to_s.include?('less') ? "#{local_pager} +G" : local_pager

    unless pager
      pager = 'tail -n 50'
      print_warning("LocalPager or $PAGER/$MANPAGER should be set. Falling back on #{pager}.")
    end

    # XXX: No vprint_status in this context?
    # XXX: VERBOSE is a string instead of Bool??
    print_status("Launching #{pager} #{path}") if framework.datastore['VERBOSE'].to_s == 'true'

    unless system(*pager.split, path)
      print_error("Could not execute #{pager} #{path}")
    end
  end

  #
  # Interact with framework's service manager
  #
  def cmd__servicemanager(*args)
    if args.include?('-h') || args.include?('--help')
      cmd__servicemanager_help
      return false
    end

    opts = {}
    @@_servicemanager_opts.parse(args) do |opt, idx, val|
      case opt
      when '-l', '--list'
        opts[:list] = true
      end
    end

    if opts.empty?
      opts[:list] = true
    end

    if opts[:list]
      table = Rex::Text::Table.new(
        'Header'  => 'Services',
        'Indent'  => 1,
        'Columns' => ['Id', 'Name', 'References']
      )
      Rex::ServiceManager.instance.each.with_index do |(name, instance), id|
        # TODO: Update rex-core to support querying the reference count
        table << [id, name, instance.instance_variable_get(:@_references)]
      end

      if table.rows.empty?
        print_status("No framework services are currently running.")
      else
        print_line(table.to_s)
      end
    end
  end

  #
  # Tab completion for the _servicemanager command
  #
  def cmd__servicemanager_tabs(_str, words)
    return [] if words.length > 1

    @@_servicemanager_opts.option_keys
  end

  def cmd__servicemanager_help
    print_line 'Usage: servicemanager'
    print_line
    print_line 'Manage running framework services'
    print @@_servicemanager_opts.usage
    print_line
  end

  #
  # Time how long in seconds a command takes to execute
  #
  def cmd_time(*args)
    if args.empty? || args.first == '-h' || args.first == '--help'
      cmd_time_help
      return true
    end

    profiler = nil
    while args.first == '--cpu' || args.first == '--memory'
      profiler = args.shift
    end

    begin
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      command = Shellwords.shelljoin(args)

      case profiler
      when '--cpu'
        Metasploit::Framework::Profiler.record_cpu do
          driver.run_single(command)
        end
      when '--memory'
        Metasploit::Framework::Profiler.record_memory do
          driver.run_single(command)
        end
      else
        driver.run_single(command)
      end
    ensure
      end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      elapsed_time = end_time - start_time
      print_good("Command #{command.inspect} completed in #{elapsed_time} seconds")
    end
  end

  def cmd_time_help
    print_line 'Usage: time [options] [command]'
    print_line
    print_line 'Time how long a command takes to execute in seconds. Also supports profiling options.'
    print_line
    print_line '   Usage:'
    print_line '      * time db_import ./db_import.html'
    print_line '      * time show exploits'
    print_line '      * time reload_all'
    print_line '      * time missing_command'
    print_line '      * time --cpu db_import ./db_import.html'
    print_line '      * time --memory db_import ./db_import.html'
    print @@time_opts.usage
    print_line
  end

  private

  def modified_files
    # Using an array avoids shelling out, so we avoid escaping/quoting
    changed_files = %w[git diff --name-only]
    begin
      output, status = Open3.capture2e(*changed_files, chdir: Msf::Config.install_root)
      is_success = status.success?
      output = output.split("\n")
    rescue => e
      elog(e)
      output = []
      is_success = false
    end
    return output, is_success
  end
end
