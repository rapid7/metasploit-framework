# -*- coding: binary -*-

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
        # @return [Array] variable names
        def get_var_names
          our_vars = code.scan(/\$[a-zA-Z\-\_0-9]+/).uniq.flatten.map(&:strip)
          our_vars.select { |v| !RESERVED_VARIABLE_NAMES.include?(v.downcase) }
        end

        #
        # Get function names from code
        #
        # @return [Array] function names
        def get_func_names
          code.scan(/function\s([a-zA-Z\-\_0-9]+)/).uniq.flatten
        end

        #
        # Attempt to find string literals in PSH expression
        #
        # @return [Array] string literals
        def get_string_literals
          code.scan(/@"(.+?)"@|@'(.+?)'@/m)
        end

        #
        # Scan code and return matches with index
        #
        # @param str [String] string to match in code
        # @param source [String] source code to match, defaults to @code
        #
        # @return [Array[String,Integer]] matched items with index
        def scan_with_index(str, source = code)
          ::Enumerator.new do |y|
            source.scan(str) do
              y << ::Regexp.last_match
            end
          end.map { |m| [m.to_s, m.offset(0)[0]] }
        end

        #
        # Return matching bracket type
        #
        # @param char [String] opening bracket character
        #
        # @return [String] matching closing bracket
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
          else
            fail ArgumentError, 'Unknown starting bracket'
          end
        end

        #
        # Extract block of code inside brackets/parenthesis
        #
        # Attempts to match the bracket at idx, handling nesting manually
        # Once the balanced matching bracket is found, all script content
        # between idx and the index of the matching bracket is returned
        #
        # @param idx [Integer] index of opening bracket
        #
        # @return [String] content between matching brackets
        def block_extract(idx)
          fail ArgumentError unless idx

          if idx < 0 || idx >= code.length
            fail ArgumentError, 'Invalid index'
          end

          start = code[idx]
          stop = match_start(start)
          delims = scan_with_index(/#{Regexp.escape(start)}|#{Regexp.escape(stop)}/, code[idx + 1..-1])
          delims.map { |x| x[1] = x[1] + idx + 1 }
          c = 1
          sidx = nil
          # Go through delims till we balance, get idx
          while (c != 0) && (x = delims.shift)
            sidx = x[1]
            x[0] == stop ? c -= 1 : c += 1
          end

          code[idx..sidx]
        end

        #
        # Extract a block of function code
        #
        # @param func_name [String] function name
        # @param delete [Boolean] delete the function from the code
        #
        # @return [String] function block
        def get_func(func_name, delete = false)
          start = code.index(func_name)

          return nil unless start

          idx = code[start..-1].index('{') + start
          func_txt = block_extract(idx)

          if delete
            delete_code = code[0..idx]
            delete_code << code[(idx + func_txt.length)..-1]
            @code = delete_code
          end

          Function.new(func_name, func_txt)
        end
      end # Parser
    end
  end
end
