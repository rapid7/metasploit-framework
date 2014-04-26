# -*- coding: binary -*-

require 'zlib'
require 'rex/text'

module Rex
module Exploitation

module Powershell

  module Obfu

    #
    # Create hash of string substitutions
    #
    def sub_map_generate(strings)
      map = {}
      strings.flatten.each do |str|
        map[str] = "$#{Rex::Text.rand_text_alpha(rand(2)+2)}"
        # Ensure our variables are unique
        while not map.values.uniq == map.values
          map[str] = "$#{Rex::Text.rand_text_alpha(rand(2)+2)}"
        end
      end
      return map
    end

    #
    # Remove comments
    #
    def strip_comments
      # Multi line
      code.gsub!(/<#(.*?)#>/m,'')
      # Single line
      code.gsub!(/^\s*#(?!.*region)(.*$)/i,'')
    end

    #
    # Remove empty lines
    #
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
    def strip_whitespace
      code.gsub!(/\s+/,' ')
    end

    #
    # Identify variables and replace them
    #
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
    def standard_subs(subs = %w{strip_comments strip_whitespace sub_funcs sub_vars} )
      # Save us the trouble of breaking injected .NET and such
      subs.delete('strip_whitespace') unless string_literals.empty?
      # Run selected modifiers
      subs.each do |modifier|
        self.send(modifier)
      end
      code.gsub!(/^$|^\s+$/,'')
      return code
    end

  end # Obfu

end
end
end

