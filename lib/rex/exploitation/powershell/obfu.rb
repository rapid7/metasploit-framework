# -*- coding: binary -*-

require 'rex/text'

module Rex
module Exploitation
module Powershell
  module Obfu
    MULTI_LINE_COMMENTS_REGEX = Regexp.new(/<#(.*?)#>/m)
    SINGLE_LINE_COMMENTS_REGEX = Regexp.new(/^\s*#(?!.*region)(.*$)/i)
    WINDOWS_EOL_REGEX = Regexp.new(/[\r\n]+/)
    UNIX_EOL_REGEX = Regexp.new(/[\n]+/)
    WHITESPACE_REGEX = Regexp.new(/\s+/)
    EMPTY_LINE_REGEX = Regexp.new(/^$|^\s+$/)

    #
    # Remove comments
    #
    # @return [String] code without comments
    def strip_comments
      # Multi line
      code.gsub!(MULTI_LINE_COMMENTS_REGEX, '')
      # Single line
      code.gsub!(SINGLE_LINE_COMMENTS_REGEX, '')

      code
    end

    #
    # Remove empty lines
    #
    # @return [String] code without empty lines
    def strip_empty_lines
      # Windows EOL
      code.gsub!(WINDOWS_EOL_REGEX, "\r\n")
      # UNIX EOL
      code.gsub!(UNIX_EOL_REGEX, "\n")

      code
    end

    #
    # Remove whitespace
    # This can break some codes using inline .NET
    #
    # @return [String] code with whitespace stripped
    def strip_whitespace
      code.gsub!(WHITESPACE_REGEX, ' ')

      code
    end

    #
    # Identify variables and replace them
    #
    # @return [String] code with variable names replaced with unique values
    def sub_vars
      # Get list of variables, remove reserved
      get_var_names.each do |var, _sub|
        code.gsub!(var, "$#{@rig.init_var(var)}")
      end

      code
    end

    #
    # Identify function names and replace them
    #
    # @return [String] code with function names replaced with unique
    #   values
    def sub_funcs
      # Find out function names, make map
      get_func_names.each do |var, _sub|
        code.gsub!(var, @rig.init_var(var))
      end

      code
    end

    #
    # Perform standard substitutions
    #
    # @return [String] code with standard substitution methods applied
    def standard_subs(subs = %w(strip_comments strip_whitespace sub_funcs sub_vars))
      # Save us the trouble of breaking injected .NET and such
      subs.delete('strip_whitespace') unless get_string_literals.empty?
      # Run selected modifiers
      subs.each do |modifier|
        send(modifier)
      end
      code.gsub!(EMPTY_LINE_REGEX, '')

      code
    end
  end # Obfu
end
end
end
