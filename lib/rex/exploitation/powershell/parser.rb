# -*- coding: binary -*-

require 'zlib'
require 'rex/text'

module Rex
module Exploitation

module Powershell

  module Parser
    # Reserved special variables
    # Acquired with: Get-Variable | Format-Table name, value -auto
    RESERVED_VARIABLE_NAMES = [
        '$$',
        '$?',
        '$^',
        '$_',
        '$args',
        '$ConfirmPreference',
        '$ConsoleFileName',
        '$DebugPreference',
        '$Env',
        '$Error',
        '$ErrorActionPreference',
        '$ErrorView',
        '$ExecutionContext',
        '$false',
        '$FormatEnumerationLimit',
        '$HOME',
        '$Host',
        '$input',
        '$LASTEXITCODE',
        '$MaximumAliasCount',
        '$MaximumDriveCount',
        '$MaximumErrorCount',
        '$MaximumFunctionCount',
        '$MaximumHistoryCount',
        '$MaximumVariableCount',
        '$MyInvocation',
        '$NestedPromptLevel',
        '$null',
        '$OutputEncoding',
        '$PID',
        '$PROFILE',
        '$ProgressPreference',
        '$PSBoundParameters',
        '$PSCulture',
        '$PSEmailServer',
        '$PSHOME',
        '$PSSessionApplicationName',
        '$PSSessionConfigurationName',
        '$PSSessionOption',
        '$PSUICulture',
        '$PSVersionTable',
        '$PWD',
        '$ReportErrorShowExceptionClass',
        '$ReportErrorShowInnerException',
        '$ReportErrorShowSource',
        '$ReportErrorShowStackTrace',
        '$ShellId',
        '$StackTrace',
        '$true',
        '$VerbosePreference',
        '$WarningPreference',
        '$WhatIfPreference'
      ].map(&:downcase).freeze

    #
    # Get variable names from code, removes reserved names from return
    #
    def get_var_names
      our_vars = code.scan(/\$[a-zA-Z\-\_]+/).uniq.flatten.map(&:strip)
      return our_vars.select {|v| !RESERVED_VARIABLE_NAMES.include?(v.downcase)}
    end

    #
    # Get function names from code
    #
    def get_func_names
      return code.scan(/function\s([a-zA-Z\-\_]+)/).uniq.flatten
    end

    # Attempt to find string literals in PSH expression
    def get_string_literals
      code.scan(/@"(.*)"@|@'(.*)'@/)
    end

    #
    # Scan code and return matches with index
    #
    def scan_with_index(str,source=code)
      ::Enumerator.new do |y|
        source.scan(str) do
          y << ::Regexp.last_match
        end
      end.map{|m| [m.to_s,m.offset(0)[0]]}
    end

    #
    # Return matching bracket type
    #
    def match_start(char)
      case char
      when '{'
        '}'
      when '('
        ')'
      when '['
        ']'
      when '<'
        '>'
      end
    end

    #
    # Extract block of code between inside brackets/parens
    #
    # Attempts to match the bracket at idx, handling nesting manually
    # Once the balanced matching bracket is found, all script content
    # between idx and the index of the matching bracket is returned
    #
    def block_extract(idx)
      start = code[idx]
      stop = match_start(start)
      delims = scan_with_index(/#{Regexp.escape(start)}|#{Regexp.escape(stop)}/,code[idx+1..-1])
      delims.map {|x| x[1] = x[1] + idx + 1}
      c = 1
      sidx = nil
      # Go through delims till we balance, get idx
      while not c == 0 and x = delims.shift do
        sidx = x[1]
        x[0] == stop ? c -=1 : c+=1
      end
      return code[idx..sidx]
    end

    def get_func(func_name, delete = false)
      start = code.index(func_name)
      idx = code[start..-1].index('{') + start
      func_txt = block_extract(idx)
      code.delete(ftxt) if delete
      return Function.new(func_name,func_txt)
    end
  end # Parser

end
end
end

