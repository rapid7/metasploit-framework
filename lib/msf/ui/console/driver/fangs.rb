require 'msf/ui/console/defanged_exception'

# The console can run in defanged mode, where dangerous internal commands and command pass-thru is disabled.
module Msf::Ui::Console::Driver::Fangs
  #
  # CONSTANTS
  #

  # The list of data store elements that cannot be set when in defanged mode.
  DEFANGED_PROHIBITED_DATA_STORE_ELEMENTS = [ "MsfModulePaths" ]

  #
  # Methods
  #

  def defanged?
    !!@defanged
  end

  # If {#defanged?}, raise an {Msf::Ui::Console::DefangedException}.  Call {#fanged!} before using
  # dangerous functionality, such as exploitation, irb, and command shell pass through is disabled to raise an exception
  # if the dangerous functionality should not be allowed.
  #
  # @raise [Msf::Ui::Console::DefangedException]
  def fanged!
    if defanged?
      raise Msf::Ui::Console::DefangedException
    end
  end
end
