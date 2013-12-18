# This exception is used to indicate that functionality is disabled due to the UI driver being in defanged mode.
class Msf::Ui::Console::DefangedException < Exception
  def initialize
    super("This functionality is currently disabled (defanged mode)")
  end
end
