# frozen_string_literal: true

require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pool'

module Rex
module Post
module Meterpreter

# Runtime exposed to manifest-provided Ruby client helpers.
class MicroHelper
  class << self
    attr_reader :command_definitions, :cleanup_handler

    # Register an operator command handled by this helper.
    #
    # @param name [String, Symbol] The command name used by `micro run`.
    # @param description [String] The command description.
    # @yieldparam arguments [Array<String>] Positional console arguments.
    # @return [void]
    def command(name, description, &handler)
      @command_definitions ||= {}
      name = name.to_s
      raise ArgumentError, "Helper command #{name} is already defined" if @command_definitions.key?(name)
      raise ArgumentError, 'Helper commands require a handler' unless handler

      @command_definitions[name] = { description: description, handler: handler }
    end

    # Register code to execute before the helper is removed.
    #
    # @yieldreturn [void]
    # @return [void]
    def on_unload(&handler)
      @cleanup_handler = handler
    end
  end

  # Build an isolated helper class from trusted Ruby source.
  #
  # @param source [String] The helper class body.
  # @param path [String] Source name used in errors and backtraces.
  # @return [Class<MicroHelper>]
  def self.compile(source, path)
    Class.new(self).tap { |helper| helper.class_eval(source, path, 1) }
  end

  attr_reader :client, :shell, :profile, :object_name, :channel_types

  # @param shell [Object] The Meterpreter console shell.
  # @param profile [String] Manifest profile name.
  # @param object_name [String] Remote object name.
  # @param channel_types [Array<String>] Channel types declared by the object.
  def initialize(shell, profile:, object_name:, channel_types:)
    @shell = shell
    @client = shell.client
    @profile = profile
    @object_name = object_name
    @channel_types = channel_types.freeze
  end

  # Return the helper command descriptions.
  #
  # @return [Hash{String => String}]
  def commands
    (self.class.command_definitions || {}).to_h { |name, definition| [name, definition[:description]] }
  end

  # Invoke one helper command.
  #
  # @param name [String] Registered command name.
  # @param arguments [Array<String>] Console arguments.
  # @return [Object] Handler result.
  def invoke_command(name, arguments)
    definition = self.class.command_definitions.fetch(name)
    instance_exec(*arguments, &definition[:handler])
  end

  # Open a pool channel provided by this helper's remote object.
  #
  # @param type [String] A channel type declared by the same object.
  # @param tlvs [Array<Hash>] Additional open-request TLVs.
  # @param flags [Integer] Core channel flags.
  # @return [Rex::Post::Meterpreter::Channels::Pool]
  def open_pool_channel(type, tlvs: [], flags: CHANNEL_FLAG_SYNCHRONOUS)
    raise ArgumentError, "Undeclared helper channel type: #{type}" unless channel_types.include?(type)

    Channel.create(client, type, Channels::Pool, flags, tlvs)
  end

  # Run the manifest-provided unload handler.
  #
  # @return [void]
  def cleanup
    instance_exec(&self.class.cleanup_handler) if self.class.cleanup_handler
  end

  %i[print print_error print_good print_line print_status print_warning].each do |method_name|
    define_method(method_name) do |message = ''|
      shell.public_send(method_name, message)
    end
  end
end

end
end
end
