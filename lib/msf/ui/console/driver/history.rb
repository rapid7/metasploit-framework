require 'msf/ui/console/driver/resource'

# Concerning the command history in `msfconsole`.
module Msf::Ui::Console::Driver::History
  # uses {Msf::Ui::Console::Driver::Resource#save_resource} to save the history.
  include Msf::Ui::Console::Driver::Resource

  # Saves the recent history to the specified file.
  #
  # @param path [String] path on disk to save the file.
  # @return [void]
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
end
