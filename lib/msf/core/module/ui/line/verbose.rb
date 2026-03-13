module Msf::Module::UI::Line::Verbose
  TRUE_REGEX = /^(y|yes|t|1|true)$/i
  # Verbose version of #print_line
  def vprint_line(msg = '')
    print_line(msg) if datastore['VERBOSE'].to_s =~ TRUE_REGEX || (!framework.nil? && framework.datastore['VERBOSE'].to_s =~ TRUE_REGEX)
  end
end
