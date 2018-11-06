
module PCAPRUB
  # The base exception for JSON errors.
  class PCAPRUBError < StandardError; end

  # This exception is raised, if a Device Binding error occurs.
  class BindingError < PCAPRUBError; end

  # This exception is raised, if the BPF Filter raises a fault
  class BPFError < PCAPRUBError; end
  
  # This exception is raised, if the libpcap Dumper raises a fault
  # deep.
  class DumperError < PCAPRUBError; end

  # Raised if unable to set underlying capture link type
  class LinkTypeError < PCAPRUBError; end

end

