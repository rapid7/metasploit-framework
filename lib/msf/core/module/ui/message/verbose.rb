module Msf::Module::UI::Message::Verbose
  # Verbose version of #print_error
  def vprint_error(msg='')
    print_error(msg) if datastore['VERBOSE'] || (!framework.nil? && framework.datastore['VERBOSE'])
  end

  alias_method :vprint_bad, :vprint_error

  # Verbose version of #print_good
  def vprint_good(msg='')
    print_good(msg) if datastore['VERBOSE'] || (!framework.nil? && framework.datastore['VERBOSE'])
  end

  # Verbose version of #print_status
  def vprint_status(msg='')
    print_status(msg) if datastore['VERBOSE'] || (!framework.nil? && framework.datastore['VERBOSE'])
  end

  # Verbose version of #print_warning
  def vprint_warning(msg='')
    print_warning(msg) if datastore['VERBOSE'] || (!framework.nil? && framework.datastore['VERBOSE'])
  end
end
