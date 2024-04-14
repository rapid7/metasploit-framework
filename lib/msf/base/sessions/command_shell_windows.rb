module Msf::Sessions

  class CommandShellWindows < CommandShell
    def initialize(*args)
      self.platform = "windows"
      super
    end

    def shell_command_token(cmd,timeout = 10)
      shell_command_token_win32(cmd,timeout)
    end

    # Convert the executable and argument array to a command that can be run in this command shell
    # @param executable [String] The process to launch
    # @param args [Array<String>] The arguments to the process
    def to_cmd(executable, args)
      self.class.to_cmd(executable, args)
    end

    # Convert the executable and argument array to a commandline that can be passed to CreateProcessAsUserW.
    # @param executable [String] The process to launch
    # @param args [Array<String>] The arguments to the process
    # @remark The difference between this and `to_cmd` is that the output of `to_cmd` is expected to be passed
    #         to cmd.exe, whereas this is expected to be passed directly to the Win32 API, anticipating that it
    #         will in turn be interpreted by CommandLineToArgvW.
    def self.argv_to_commandline(executable, args)
      space_chars = [' ', '\t', '\v']

      # The first argument is treated differently for the purposes of backslash escaping (and should not contain double-quotes)
      needs_quoting = space_chars.any? do |char|
        executable.include?(char)
      end

      if needs_quoting
        executable = "\"#{executable}\""
      end

      escaped_args = args.map do |arg|
        needs_quoting = space_chars.any? do |char|
          arg.include?(char)
        end

        # Fix the weird behaviour when backslashes are treated differently when immediately prior to a double-quote
        # We need to send double the number of backslashes to make it work as expected
        # See: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw#remarks
        arg = arg.gsub(/(\\*)"/, '\\1\\1"')

        # Quotes need to be escaped
        arg = arg.gsub('"', '\\"')

        if needs_quoting
          # At the end of the argument, we're about to add another quote - so any backslashes need to be doubled here too
          arg = arg.gsub(/(\\*)$/, '\\1\\1')
          arg = "\"#{arg}\""
        end

        # Empty string needs to be coerced to have a value
        arg = '""' if arg == ''

        arg
      end

      cmd_and_args = [executable] + escaped_args

      cmd_and_args.join(' ')
    end

    # Convert the executable and argument array to a command that can be run in this command shell
    # @param executable [String] The process to launch
    # @param args [Array<String>] The arguments to the process
    def self.to_cmd(executable, args)
      # The space, caret and quote chars need to be inside double-quoted strings.
      # The percent character needs to be escaped using a caret char, while being outside a double-quoted string.
      #
      # Situations where these two situations combine are going to be the trickiest cases: something that has quote-requiring
      # characters (e.g. spaces), but which also needs to avoid expanding an environment variable. In this case,
      # the string needs to end up being partially quoted; with parts of the string in quotes, but others (i.e. bits with percents) not.
      # For example:
      # 'env var is %temp%, yes, %TEMP%' needs to end up as '"env var is "^%temp^%", yes, "^%TEMP^%'
      #
      # There is flexibility in how you might implement this, but I think this one looks the most "human" to me,
      # which would make it less signaturable.
      #
      # To do this, we'll consider each argument character-by-character. Each time we encounter a percent sign, we break out of any quotes
      # (if we've been inside them in the current "token"), and then start a new "token".

      cmd_and_args = [executable] + args
      quote_requiring = ['"', '^', ' ', "\t", "\v", '&', '<', '>', '|']

      escaped_cmd_and_args = cmd_and_args.map do |arg|
        # Double-up all quote chars
        arg = arg.gsub('"', '""')

        # Now the fun begins
        current_token = ""
        result = ""
        in_quotes = false

        arg.each_char do |char|
          if char == '%'
            if in_quotes
              # This token has been in an inside-quote context, so let's properly wrap that before continuing
              current_token = "\"#{current_token}\""
            end
            result += current_token
            result += '^%' # Escape the offending percent

            # Start a new token - we'll assume we're remaining outside quotes
            current_token = ''
            in_quotes = false
            next
          elsif quote_requiring.include?(char)
            # Oh, it turns out we should have been inside quotes for this token.
            # Let's note that, so that when we actually append the token
            in_quotes = true
          end
          current_token += char
        end

        if in_quotes
          # This token has been in an inside-quote context, so let's properly wrap that before continuing
          current_token = "\"#{current_token}\""
        end
        result += current_token

        # Fix the weird behaviour when backslashes are treated differently when immediately prior to a double-quote
        # We need to send double the number of backslashes to make it work as expected
        # See: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw#remarks
        result.gsub!(/(\\*)"/, '\\1\\1"')

        # Empty string needs to be coerced to have a value
        result = '""' if result == ''

        result
      end

      escaped_cmd_and_args.join(' ')
    end
  end

end
