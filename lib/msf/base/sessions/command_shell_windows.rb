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
      self.class.to_cmd
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
      quote_requiring = ['"', '^', ' ', '&', '<', '>', '|']

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

        result
      end

      escaped_cmd_and_args.join(' ')
    end
  end

end
