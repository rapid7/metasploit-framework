module Msf::Ui::Console::CommandDispatcher::Core::Spool
  def cmd_spool(*args)
    if args.include?('-h') or args.empty?
      cmd_spool_help
      return
    end

    message_by_type = {}
    color = driver.output.config[:color]

    if args[0] == "off"
      driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)
      message_by_type[:good] = "Updating progress bars (as from reload_all) are re-enabled"
      message_by_type[:status] = "Spooling is now disabled"
    else
      driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(args[0]))
      message_by_type[:warning] = "Updating progress bars (as from reload_all) will now be disabled: progress bars will only print when complete"
      message_by_type[:status] = "Spooling to file #{args[0]}...\n"
    end

    # Restore color and prompt
    driver.output.config[:color] = color
    prompt = framework_prompt

    if active_module
      # intentionally += and not << because we don't want to modify framework_prompt
      prompt += " #{active_module.type}(%bld%red#{active_module.shortname}%clr)"
    end

    driver.update_prompt("#{prompt} ", framework_prompt_char, true)

    [:good, :warning, :status].each do |type|
      message = message_by_type[type]

      if message
        send("print_#{type}", message)
      end
    end

    return
  end

  def cmd_spool_help
    print_line "Usage: spool <off>|<filename>"
    print_line
    print_line "Example:"
    print_line "  spool /tmp/console.log"
    print_line
  end

  def commands
    super.merge(
        "spool" => "Write console output into a file as well the screen"
    )
  end
end
