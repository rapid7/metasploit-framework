require 'daemons/pid'

module Daemons
  class PidMem < Pid
    attr_accessor :pid

    def self.existing(numeric_pid)
      new_instance = PidMem.allocate

      new_instance.instance_variable_set(:@pid, numeric_pid)

      new_instance
    end
  end
end
