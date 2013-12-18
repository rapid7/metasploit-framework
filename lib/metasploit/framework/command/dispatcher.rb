# @note This module and its API is a temporary measure until all commands are converted to
#   `Metasploit::Framework::Command::Base` subclasses, at which time the dispatcher will just automatically use the
#    command classes in the correct manner.
#
# Allows a command dispatcher to declare which commands it supports and to have those commands automatically wired to
# the methods it expects.
module Metasploit::Framework::Command::Dispatcher
  extend ActiveSupport::Concern

  module ClassMethods
    # Declares a command that this dispatcher can dispatch.  Declares cmd_<name>, cmd_<name>_help, and cmd_<name>_tabs
    # methods on the dispatcher which use the Metasploit::Framework::Command::<name> class.
    #
    # @return [void]
    def command(name)
      inherit = false
      module_name = name.to_s.camelize

      # Define methods in an included module so that super calls from inside the class call methods defined dynamically
      if const_defined?(module_name, inherit)
        command_module = const_get(module_name, inherit)
      else
        command_module = const_set(module_name, Module.new)
        include command_module
      end

      method_prefix = "cmd_#{name}"
      command_class = "Metasploit::Framework::Command::#{name.to_s.camelize}".constantize

      command_module.module_eval do
        define_method(method_prefix) do |*words|
          command = command_class.new(
              dispatcher: self,
              words: words
          )
          command.run
        end

        define_method("#{method_prefix}_help") do
          send(method_prefix, '--help')
        end

        define_method("#{method_prefix}_tabs") do |partial_word, words|
          # first word is always command name
          command_words = words[1 .. -1]
          command = command_class.new(
              dispatcher: self,
              partial_word: partial_word,
              words: command_words
          )
          command.tab_completions
        end

        define_method(:commands) do
          # have to call with () when calling super instead define_method
          super().merge(
              name.to_s => command_class.description
          )
        end
      end
    end
  end
end