# -*- coding: binary -*-

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

      func_regex = /\[(\w+\[\])\]\$(\w+)\s?=|\[(\w+)\]\$(\w+)\s?=|\[(\w+\[\])\]\s+?\$(\w+)\s+=|\[(\w+)\]\s+\$(\w+)\s?=/i
      #func_regex = /\[(\w+\[\])\]\.?\$(\w+)\s?=|\[(\w+)\]\s?\$(\w+)\s?=/i
      matches = pclause.scan(func_regex)

      # Ignore assignment, create params with class and variable names
      matches.each do |param|
        klass = nil
        name = nil
        param.each do |value|
          if value
            if klass
              name = value
              @params << Param.new(klass,name)
              break
            else
              klass = value
            end
          end
        end
      end
    end
  end

end
end
end

