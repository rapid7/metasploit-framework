# -*- coding: binary -*-
require 'rex/post/hwbridge'
require 'msf/core/auxiliary/report'
require 'rex/parser/arguments'

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
  # Loaded from core and passed hash from custom_methods rest call
  #
  def load_methods(m)
    @custom_methods = m
    m.each do |method|
      if method.key? "method_name"
        desc = "See HW manual for command description"
        desc = method["method_desc"] if method.key? "method_desc"
        cmd = method["method_name"]
        cmd = /\/(\S+)$/.match(cmd)
        @cmds[cmd] = method["method_desc"]
        eval("alias cmd_#{cmd} cmd_generic_handler")
      end
    end
  end

  #
  # A generic help system to show the arguments needed for custom commands
  #
  def cmd_generic_handler_help(cmd)
    @custom_methods.each do |meth|
      next unless meth["method_name"] =~ /#{cmd}$/
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
  end

  #
  # A generic handler for all custom commands
  #
  def cmd_generic_handler(*args)
    cmd = __callee__.to_s.gsub(/^cmd_/,'')
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
      if meth["method_name"] =~ /#{cmd}$/
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

