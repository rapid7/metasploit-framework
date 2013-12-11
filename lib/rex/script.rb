# -*- coding: binary -*-

module Rex

###
#
# This class provides an easy interface for loading and executing ruby
# scripts.
#
###
module Script

  class Completed < ::RuntimeError
  end

  #
  # Reads the contents of the supplied file and exeutes them.
  #
  def self.execute_file(file, in_binding = nil)
    str = ''
    buf = ::File.read(file, ::File.size(file))
    execute(buf, in_binding)
  end

  #
  # Executes arbitrary ruby from the supplied string.
  #
  def self.execute(str, in_binding = nil)
    begin
      eval(str, in_binding)
    rescue Completed
    end
  end

end

end

require 'rex/script/base'
require 'rex/script/shell'
require 'rex/script/meterpreter'

