
module Daemons

  class Exception < ::RuntimeError
  end
  
  class RuntimeException < Exception
  end
  
  class CmdException < Exception
  end
  
  class Error < Exception
  end
  
  class SystemError < Error
  
    attr_reader :system_error
    
    def initialize(msg, system_error)
      super(msg)
      
      @system_error = system_error
    end
    
  end
  
end