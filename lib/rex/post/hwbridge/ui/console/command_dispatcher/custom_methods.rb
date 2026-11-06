# -*- coding: binary -*-
require 'rex/post/hwbridge'
require 'rex/post/hwbridge/extensions/custom_methods/custom_methods'

module Rex
module Post
module HWBridge
module Ui
###
# Custom Methods extension - a set of commands defined by the HW itself
###
class Console::CommandDispatcher::CustomMethods
  include Console::CommandDispatcher
  include Msf::Auxiliary::Report

  def initialize(shell)
    super
    @cmds = {}
    @custom_methods = {}
  end

  @@generic_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help menu."                    ])

  #
  # List of supported commands.
  #
  def commands
    @cmds ||= {}
  end

  def name
    "Custom Methods"
  end

  #
  # Loaded from core and passed hash from custom_methods rest call.
  #
  # Only the trailing path segment of method_name is used as the command
  # name. Entries with an unsupported path or an existing command name are
  # skipped. The remaining entries are kept with 'args' as an array of hashes.
  #
  # Calling this again replaces the commands registered by an earlier call.
  #
  # @param methods [Array<Hash>] The method definitions from the hardware's
  #   custom_methods reply. Each definition has a 'method_name' string, and
  #   can have 'method_desc', 'args' and 'return'.
  # @return [void]
  #
  def load_methods(methods)
    unless methods.is_a?(Array)
      print_error('Failed to load custom methods: expected an array')
      return
    end

    unload_methods
    methods.each do |method|
      next unless method.is_a?(Hash) && method['method_name'].is_a?(String)

      full_name = method['method_name']
      cmd = Rex::Post::HWBridge::Extensions::CustomMethods::CustomMethods.command_name(full_name)

      unless cmd
        print_error("Skipping custom method with unsupported name: #{full_name.inspect}")
        next
      end

      if command_name_in_use?(cmd)
        print_error("Skipping custom method #{full_name.inspect}: the command '#{cmd}' already exists")
        next
      end

      arg_list = method.fetch('args', [])
      valid_args = arg_list.is_a?(Array) && arg_list.all? do |arg|
        arg.is_a?(Hash) &&
          arg['arg_name'].is_a?(String) && !arg['arg_name'].empty? &&
          [true, false].include?(arg.fetch('required', false))
      end
      unless valid_args
        print_error("Skipping custom method #{full_name.inspect}: invalid arguments")
        next
      end

      @custom_methods << method.merge('args' => arg_list)
      @cmds[cmd] = method['method_desc'] || 'See HW manual for command description'
      define_singleton_method("cmd_#{cmd}") do |*args|
        cmd_generic_handler(cmd, *args)
      end
    end
  end

  #
  # Removes the commands registered by an earlier load_methods call, so the
  # same commands can be registered again.
  #
  # @return [void]
  #
  def unload_methods
    @cmds.each_key do |cmd|
      handler = :"cmd_#{cmd}"
      singleton_class.remove_method(handler) if singleton_methods(false).include?(handler)
    end
    @cmds.clear
    @custom_methods = []
  end

  #
  # Whether a command called cmd is already provided, either by this
  # dispatcher (including its own handlers and earlier custom methods) or by
  # any other dispatcher in the shell.
  #
  # @param cmd [String] The command name, without the cmd_ prefix
  # @return [Boolean]
  #
  def command_name_in_use?(cmd)
    return true if respond_to?("cmd_#{cmd}", true)

    shell.dispatcher_stack.any? do |dispatcher|
      !dispatcher.equal?(self) && dispatcher.commands&.key?(cmd)
    end
  end

  #
  # A generic help system to show the arguments needed for custom commands
  #
  def cmd_generic_handler_help(cmd)
    @custom_methods.each do |meth|
      next unless meth["method_name"].split('/').last == cmd
      args = ""
      args = "<args>" if meth["args"].size > 0
      print_line("Usage: #{cmd} #{args}")
      print_line
      meth["args"].each do |arg|
        req = ""
        req = "  *required*" if arg.key? "required" and arg["required"] == true
        print_line("  #{arg["arg_name"]}=<#{arg["arg_type"]}> #{req}")
      end
    end
  end

  #
  # A generic handler for all custom commands
  #
  def cmd_generic_handler(cmd, *args)
    @@generic_opts.parse(args) { |opt, idx, val|
      case opt
      when "-h"
        cmd_generic_handler_help(cmd)
        return true
      end
    }
    if not has_required_args(cmd, args)
      print_error("Not all required arguments were used.  See command help (-h)")
      return true
    end
    res = client.custom_methods.send_request(cmd, args, @custom_methods)
    print_status(res["status"]) if res.key? "status"
    print_status(res["value"]) if res.key? "value"
  end

  #
  # Verify all required args are used
  #
  def has_required_args(cmd, args)
    all_found = true
    arguments = {}
    args.each do |arg|
      (key, value) = arg.split('=')
      arguments[key] = value
    end
    @custom_methods.each do |meth|
      if meth["method_name"].split('/').last == cmd
        meth["args"].each do |arg|
          if arg.key? "required" and arg["required"] == true
            all_found = false if not arguments.key? arg["arg_name"]
          end
        end
      end
    end
    all_found
  end

end

end
end
end
end

