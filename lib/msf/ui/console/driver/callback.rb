module Msf::Ui::Console::Driver::Callback
  require 'msf/ui/console/driver/callback/variable'
  include Msf::Ui::Console::Driver::Callback::Variable

  #
  # Called before things actually get rolling such that banners can be
  # displayed, scripts can be processed, and other fun can be had.
  #
  def on_startup(opts = {})
    framework.events.on_ui_start(Msf::Framework::Revision)

    run_single("banner") unless opts['DisableBanner']

    opts["Plugins"].each do |plug|
      run_single("load '#{plug}'")
    end if opts["Plugins"]

    self.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
  end
end