module Msf::Module::UI::Line::Verbose
  # Verbose version of #print_line
  def vprint_line(msg='')
    print_line(msg) if datastore['VERBOSE'] || framework.datastore['VERBOSE']
  end
end
