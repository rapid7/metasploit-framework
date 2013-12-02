require 'ruby-progressbar'

module Msf::Ui::Console::CommandDispatcher::Core::ReloadAll
  #
  # CONSTANTS
  #

  # <title> <count>/<total> |<progress_bar with percentage>|
  PROGRESS_BAR_FORMAT = '%t %c/%C |%w>%i|'

  #
  # Methods
  #

  #
  # Reload all module paths that we are aware of
  #
  def cmd_reload_all(*args)
    if args.length > 0
      cmd_reload_all_help
    else
      print_status("Reloading modules from all module paths...")
      self.framework.modules.cache.prefetch(
          changed: true,
          progress_bar_factory: method(:cmd_reload_all_progress_bar_factory)
      )
      cmd_banner
    end
  end

  def cmd_reload_all_help
    print_line "Usage: reload_all"
    print_line
    print_line "Reload all modules from all configured module paths.  This may take awhile."
    print_line "See also: loadpath"
    print_line
  end

  def cmd_reload_all_progress_bar_factory
    ProgressBar.create(
        format: PROGRESS_BAR_FORMAT,
        output: self
    )
  end

  def commands
    super.merge(
        "reload_all" => 'Reloads all modules from all defined module paths'
    )
  end
end
