# frozen_string_literal: true

require 'rex/post/meterpreter/ui/console/command_dispatcher'

module Rex
module Post
module Meterpreter
module Ui

class Console::CommandDispatcher::MicroAlias
  include Console::CommandDispatcher

  def initialize(shell)
    super

    @core_dispatcher = shell.dispatcher_stack.find { |dispatcher| dispatcher.is_a?(Console::CommandDispatcher::Core) }
  end

  def commands
    @core_dispatcher.micro_alias_dispatcher_commands
  end

  def name
    'Micro Alias'
  end

  def method_missing(method_name, *arguments)
    method = method_name.to_s
    alias_name = method.delete_prefix('cmd_') if method.start_with?('cmd_')
    return @core_dispatcher.micro_invoke_alias(alias_name, arguments) if alias_name && commands.key?(alias_name)

    super
  end

  def respond_to_missing?(method_name, include_private = false)
    method = method_name.to_s
    (method.start_with?('cmd_') && commands.key?(method.delete_prefix('cmd_'))) || super
  end
end

end
end
end
end
