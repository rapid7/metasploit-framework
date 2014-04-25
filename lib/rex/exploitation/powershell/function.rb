# -*- coding: binary -*-

require 'rex/text'

module Rex
module Exploitation

module Powershell

  class Function
    attr_accessor :code, :name, :params

    include Output
    include Parser
    include Obfu

    def initialize(name,code)
      @name = name
      @code = code
      populate_params
    end

    #
    # To String
    #
    # @return [String] Powershell function
    def to_s
      "function #{name} #{code}"
    end

    #
    # Identify the parameters from the code and
    # store as Param in @params
    #
    def populate_params
      @params = []
      start = code.index(/param\s+\(|param\(/im)
      return unless start
      # Get start of our block
      idx = scan_with_index('(',code[start..-1]).first.last + start
      pclause = block_extract(idx)
      # Keep lines which declare a variable of some class
      vars = pclause.split(/\n|;/).select {|e| e =~ /\]\$\w/}
      vars.map! {|v| v.split('=',2).first}.map(&:strip)
      # Ignore assignment, create params with class and variable names
      vars.map {|e| e.split('$')}.each do |klass,name|
        @params << Param.new(klass,name)
      end
    end
  end

end
end
end

