# -*- coding: binary -*-

require 'rex/text'

module Rex
module Exploitation

module Powershell

  module Obfu

    #
    # Create hash of string substitutions
    #
    # @param strings [Array] array of strings to generate unique names
    #
    # @return [Hash] map of strings with new unique names
    def sub_map_generate(strings)
      map = {}
      strings.flatten.each do |str|
        @rig.init_var(str)
        map[str] = @rig[str]
      end

      map
    end

    #
    # Remove comments
    #
    # @return [String] code without comments
    def strip_comments
      # Multi line
      code.gsub!(/<#(.*?)#>/m,'')
      # Single line
      code.gsub!(/^\s*#(?!.*region)(.*$)/i,'')
    end

    #
    # Remove empty lines
    #
    # @return [String] code without empty lines
    def strip_empty_lines
      # Windows EOL
      code.gsub!(/[\r\n]+/,"\r\n")
      # UNIX EOL
      code.gsub!(/[\n]+/,"\n")
    end

    #
    # Remove whitespace
    # This can break some codes using inline .NET
    #
    # @return [String] code with whitespace stripped
    def strip_whitespace
      code.gsub!(/\s+/,' ')
    end

    #
    # Identify variables and replace them
    #
    # @return [String] code with variable names replaced with unique values
    def sub_vars
      # Get list of variables, remove reserved
      vars = get_var_names
      # Create map, sub key for val
      sub_map_generate(vars).each do |var,sub|
        code.gsub!(var,sub)
      end
    end

    #
    # Identify function names and replace them
    #
    # @return [String] code with function names replaced with unique
    #   values
    def sub_funcs
      # Find out function names, make map
      # Sub map keys for values
      sub_map_generate(get_func_names).each do |var,sub|
        code.gsub!(var,sub)
      end
    end

    #
    # Perform standard substitutions
    #
    # @return [String] code with standard substitution methods applied
    def standard_subs(subs = %w{strip_comments strip_whitespace sub_funcs sub_vars} )
      # Save us the trouble of breaking injected .NET and such
      subs.delete('strip_whitespace') unless string_literals.empty?
      # Run selected modifiers
      subs.each do |modifier|
        self.send(modifier)
      end
      code.gsub!(/^$|^\s+$/,'')

      code
    end

  end # Obfu

end
end
end

