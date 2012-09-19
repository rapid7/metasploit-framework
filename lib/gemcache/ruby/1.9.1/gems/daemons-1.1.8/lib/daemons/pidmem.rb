require 'daemons/pid'


module Daemons

  class PidMem < Pid
    attr_accessor :pid
    
    def PidMem.existing(numeric_pid)
      new_instance = PidMem.allocate
      
      new_instance.instance_variable_set(:@pid, numeric_pid)
      
      return new_instance
    end
    
  end

end
