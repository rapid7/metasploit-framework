module Msf::Sessions

  class CommandShellWindows < CommandShell
    def initialize(*args)
      self.platform = "windows"
      super
    end

    def self.space_chars
      [' ', '\t', '\v']
    end

    def shell_command_token(cmd,timeout = 10)
      shell_command_token_win32(cmd,timeout)
    end

    # Convert the executable and argument array to a command that can be run in this command shell
    # @param cmd_and_args [Array<String>] The process path and the arguments to the process
    def to_cmd(cmd_and_args)
      self.class.to_cmd(cmd_and_args)
    end

    # Escape a process for the command line
    # @param executable [String] The process to launch
    def self.escape_cmd(executable)
      needs_quoting = space_chars.any? do |char|
        executable.include?(char)
      end

      if needs_quoting
        executable = "\"#{executable}\""
      end

      executable
    end

    # Convert the executable and argument array to a commandline that can be passed to CreateProcessAsUserW.
    # @param args [Array<String>] The arguments to the process
    # @remark The difference between this and `to_cmd` is that the output of `to_cmd` is expected to be passed
    #         to cmd.exe, whereas this is expected to be passed directly to the Win32 API, anticipating that it
    #         will in turn be interpreted by CommandLineToArgvW.
    def self.argv_to_commandline(args)
      escaped_args = args.map do |arg|
        escape_arg(arg)
      end

      escaped_args.join(' ')
    end

    # Escape an individual argument per Windows shell rules
    # @param arg [String] Shell argument
    def self.escape_arg(arg)
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

    # Convert the executable and argument array to a command that can be run in this command shell
    # @param cmd_and_args [Array<String>] The process path and the arguments to the process
    def self.to_cmd(cmd_and_args)
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

      quote_requiring = ['"', '^', ' ', "\t", "\v", '&', '<', '>', '|']

      escaped_cmd_and_args = cmd_and_args.map do |arg|
        # Escape quote chars by doubling them up, except those preceeded by a backslash (which are already effectively escaped, and handled below)
        arg = arg.gsub(/([^\\])"/, '\\1""')
        arg = arg.gsub(/^"/, '""')

        result = CommandShell._glue_cmdline_escape(arg, quote_requiring, '%', '^%', '"')

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
