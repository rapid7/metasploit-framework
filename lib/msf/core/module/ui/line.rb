module Msf::Module::UI::Line
  def print_line(msg='')
    super(print_line_prefix + msg)
  end

  def print_line_prefix
    datastore['CustomPrintPrefix'] || framework.datastore['CustomPrintPrefix'] || ''
  end
end
