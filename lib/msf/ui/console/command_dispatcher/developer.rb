# -*- coding: binary -*-

class Msf::Ui::Console::CommandDispatcher::Developer

  include Msf::Ui::Console::CommandDispatcher

  @@irb_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help menu.'             ],
    '-e' => [true,  'Expression to evaluate.']
  )

  def initialize(driver)
    super
  end

  def name
    'Developer'
  end

  def commands
    {
      'irb'        => 'Open an interactive Ruby shell in the current context',
      'pry'        => 'Open the Pry debugger on the current module or Framework',
      'edit'       => 'Edit the current module or a file with the preferred editor',
      'reload_lib' => 'Reload Ruby library files from specified paths',
      'log'        => 'Display framework.log paged to the end if possible'
    }
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

  def reload_changed_files
    # Using an array avoids shelling out, so we avoid escaping/quoting
    changed_files = %w[git diff --name-only]

    output, status = Open3.capture2e(*changed_files, chdir: Msf::Config.install_root)

    unless status.success?
      print_error("Git is not available: #{output.chomp}")
      return
    end

    files = output.split("\n")

    files.each do |file|
      f = File.join(Msf::Config.install_root, file)
      reload_file(file, print_errors: false)
    end
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
  def cmd_irb_tabs(str, words)
    return [] if words.length > 1
    @@irb_opts.fmt.keys
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

    unless active_module
      print_status("You are in the \"framework\" object\n")
      framework.pry
      return
    end

    print_status("You are in #{active_module.fullname}\n")
    active_module.pry
  end

  def cmd_edit_help
    print_line 'Usage: edit [file/to/edit]'
    print_line
    print_line "Edit the currently active module or a local file with #{local_editor}."
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
        return reload_changed_files
      end
    end

    # The remaining unparsed arguments are files
    files = options.order(args)

    return print(options.help) if files.empty?

    files.each { |file| reload_file(file) }
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

end
