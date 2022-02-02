module Msf::Module::UI::Line
  autoload :Verbose, 'msf/core/module/ui/line/verbose'

  include Msf::Module::UI::Line::Verbose

  def print_line(msg='')
    super(print_line_prefix + msg)
  end

  def print_line_prefix
    datastore['CustomPrintPrefix'] || framework.datastore['CustomPrintPrefix'] || ''
  end
end
