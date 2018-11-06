module RSpec
  module Core
    # @private
    # Deals with the fact that `shellwords` only works on POSIX systems.
    module ShellEscape
      module_function

      def quote(argument)
        "'#{argument.to_s.gsub("'", "\\\\'")}'"
      end

      if RSpec::Support::OS.windows?
        # :nocov:
        alias escape quote
        # :nocov:
      else
        require 'shellwords'

        def escape(shell_command)
          Shellwords.escape(shell_command.to_s)
        end
      end

      # Known shells that require quoting: zsh, csh, tcsh.
      #
      # Feel free to add other shells to this list that are known to
      # allow `rspec ./some_spec.rb[1:1]` syntax without quoting the id.
      #
      # @private
      SHELLS_ALLOWING_UNQUOTED_IDS = %w[ bash ksh fish ]

      def conditionally_quote(id)
        return id if shell_allows_unquoted_ids?
        quote(id)
      end

      def shell_allows_unquoted_ids?
        # Note: ENV['SHELL'] isn't necessarily the shell the user is currently running.
        # According to http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap08.html:
        # "This variable shall represent a pathname of the user's preferred command language interpreter."
        #
        # It's the best we can easily do, though. We err on the side of safety (quoting
        # the id when not actually needed) so it's not a big deal if the user is actually
        # using a different shell.
        SHELLS_ALLOWING_UNQUOTED_IDS.include?(ENV['SHELL'].to_s.split('/').last)
      end
    end
  end
end
