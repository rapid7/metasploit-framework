# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects outdated usage of the `cmd_exec` API where arguments are passed as a second parameter.
      # The modern API is `create_process(executable, args: [])` which properly handles argument arrays.
      #
      # `cmd_exec` should only be used with a single static command string. When you need to pass
      # arguments or construct commands dynamically, use `create_process` instead.
      #
      # @example
      #   # bad - outdated API with args parameter
      #   cmd_exec('cmd.exe', '/c echo hello')
      #   cmd_exec(binary, args, timeout)
      #   cmd_exec("ls", "-la /tmp")
      #
      #   # good - static command strings
      #   cmd_exec('id -u')
      #   cmd_exec('hostname')
      #   cmd_exec("echo $PPID")
      #
      #   # good - modern API with args array
      #   create_process('cmd.exe', args: ['/c', 'echo', 'hello'])
      #   create_process(binary, args: args_array, time_out: timeout)
      class DetectOutdatedCmdExecApi < Base
        MSG = 'Do not use cmd_exec with separate arguments. ' \
              "Use create_process with an args array instead use: `create_process(executable, args: [], time_out: 15, opts: {})`"

        # Called for every method in the code
        # Checks if it's a cmd_exec call with separate arguments and registers an offense if so
        # @param node [RuboCop::AST::SendNode] The method call node being checked
        def on_send(node)
          return unless cmd_exec_with_args?(node)

          add_offense(node, message: MSG)
        end

        private

        # Check if this is a cmd_exec call with a second argument (args parameter)
        # @param node [RuboCop::AST::SendNode]
        # @return [Boolean]
        def cmd_exec_with_args?(node)
          return false unless node.method_name == :cmd_exec

          # cmd_exec with 2 or more arguments (cmd, args, ...) is outdated
          # cmd_exec with 1 argument (just the command) is acceptable
          node.arguments.length >= 2 && !nil_second_arg?(node)
        end

        # Check if the second argument is explicitly nil
        # cmd_exec(cmd, nil, timeout) might be used to skip args but set timeout
        # @param node [RuboCop::AST::SendNode]
        # @return [Boolean]
        def nil_second_arg?(node)
          return false if node.arguments.length < 2

          second_arg = node.arguments[1]
          # Use nil_type? to check if the node represents a nil literal in the code (e.g., `nil`)
          second_arg.nil_type?
        end
      end
    end
  end
end
