module Msf::Module::UI
  autoload :Message, 'msf/core/module/ui/message'

  # Modules can subscribe to a user-interface, and as such they include the
  # UI subscriber module.  This provides methods like print, print_line, etc.
  # User interfaces are designed to be medium independent, and as such the
  # user interface subscribes are designed to provide a flexible way of
  # interacting with the user, n stuff.
  include Rex::Ui::Subscriber

  # Overwrite the {Rex::Ui::Subscriber} print_(status|error|good) to do time stamps
  include Msf::Module::UI::Message
end