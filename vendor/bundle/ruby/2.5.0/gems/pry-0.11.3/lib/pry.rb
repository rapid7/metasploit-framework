# (C) John Mair (banisterfiend) 2016
# MIT License
#
require 'pp'
require 'pry/forwardable'
require 'pry/input_lock'
require 'pry/exceptions'
require 'pry/platform'
require 'pry/helpers/base_helpers'
require 'pry/hooks'

class Pry
  # The default hooks - display messages when beginning and ending Pry sessions.
  DEFAULT_HOOKS = Pry::Hooks.new.add_hook(:before_session, :default) do |out, target, _pry_|
    next if _pry_.quiet?
    _pry_.run_command("whereami --quiet")
  end

  # The default print
  DEFAULT_PRINT = proc do |output, value, _pry_|
    _pry_.pager.open do |pager|
      pager.print _pry_.config.output_prefix
      Pry::ColorPrinter.pp(value, pager, Pry::Terminal.width! - 1)
    end
  end

  # may be convenient when working with enormous objects and
  # pretty_print is too slow
  SIMPLE_PRINT = proc do |output, value|
    begin
      output.puts value.inspect
    rescue RescuableException
      output.puts "unknown"
    end
  end

  # useful when playing with truly enormous objects
  CLIPPED_PRINT = proc do |output, value|
    output.puts Pry.view_clip(value, id: true)
  end

  # Will only show the first line of the backtrace
  DEFAULT_EXCEPTION_HANDLER = proc do |output, exception, _|
    if UserError === exception && SyntaxError === exception
      output.puts "SyntaxError: #{exception.message.sub(/.*syntax error, */m, '')}"
    else
      output.puts "#{exception.class}: #{exception.message}"
      output.puts "from #{exception.backtrace.first}"
    end
  end

  DEFAULT_PROMPT_NAME = 'pry'

  # The default prompt; includes the target and nesting level
  DEFAULT_PROMPT = [
                    proc { |target_self, nest_level, pry|
                      "[#{pry.input_array.size}] #{pry.config.prompt_name}(#{Pry.view_clip(target_self)})#{":#{nest_level}" unless nest_level.zero?}> "
                    },

                    proc { |target_self, nest_level, pry|
                      "[#{pry.input_array.size}] #{pry.config.prompt_name}(#{Pry.view_clip(target_self)})#{":#{nest_level}" unless nest_level.zero?}* "
                    }
                   ]

  DEFAULT_PROMPT_SAFE_OBJECTS = [String, Numeric, Symbol, nil, true, false]

  # A simple prompt - doesn't display target or nesting level
  SIMPLE_PROMPT = [proc { ">> " }, proc { " | " }]

  NO_PROMPT = [proc { '' }, proc { '' }]

  SHELL_PROMPT = [
                  proc { |target_self, _, _pry_| "#{_pry_.config.prompt_name} #{Pry.view_clip(target_self)}:#{Dir.pwd} $ " },
                  proc { |target_self, _, _pry_| "#{_pry_.config.prompt_name} #{Pry.view_clip(target_self)}:#{Dir.pwd} * " }
                 ]

  # A prompt that includes the full object path as well as
  # input/output (_in_ and _out_) information. Good for navigation.
  NAV_PROMPT = [
                proc do |_, _, _pry_|
                  tree = _pry_.binding_stack.map { |b| Pry.view_clip(b.eval("self")) }.join " / "
                  "[#{_pry_.input_array.count}] (#{_pry_.config.prompt_name}) #{tree}: #{_pry_.binding_stack.size - 1}> "
                end,
                proc do |_, _, _pry_|
                  tree = _pry_.binding_stack.map { |b| Pry.view_clip(b.eval("self")) }.join " / "
                  "[#{_pry_.input_array.count}] (#{ _pry_.config.prompt_name}) #{tree}: #{_pry_.binding_stack.size - 1}* "
                end,
               ]

  # Deal with the ^D key being pressed. Different behaviour in different cases:
  #   1. In an expression behave like `!` command.
  #   2. At top-level session behave like `exit` command.
  #   3. In a nested session behave like `cd ..`.
  DEFAULT_CONTROL_D_HANDLER = proc do |eval_string, _pry_|
    if !eval_string.empty?
      eval_string.replace('') # Clear input buffer.
    elsif _pry_.binding_stack.one?
      _pry_.binding_stack.clear
      throw(:breakout)
    else
      # Otherwise, saves current binding stack as old stack and pops last
      # binding out of binding stack (the old stack still has that binding).
      _pry_.command_state["cd"] ||= Pry::Config.from_hash({}) # FIXME
      _pry_.command_state['cd'].old_stack = _pry_.binding_stack.dup
      _pry_.binding_stack.pop
    end
  end

  DEFAULT_SYSTEM = proc do |output, cmd, _|
    if !system(cmd)
      output.puts "Error: there was a problem executing system command: #{cmd}"
    end
  end

  # Store the current working directory. This allows show-source etc. to work if
  # your process has changed directory since boot. [Issue #675]
  INITIAL_PWD = Dir.pwd

  # This is to keep from breaking under Rails 3.2 for people who are doing that
  # IRB = Pry thing.
  module ExtendCommandBundle; end
end

require 'method_source'
require 'shellwords'
require 'stringio'
require 'strscan'
require 'coderay'
require 'pry/slop'
require 'rbconfig'
require 'tempfile'
require 'pathname'

require 'pry/version'
require 'pry/repl'
require 'pry/rbx_path'
require 'pry/code'
require 'pry/history_array'
require 'pry/helpers'
require 'pry/code_object'
require 'pry/method'
require 'pry/wrapped_module'
require 'pry/history'
require 'pry/command'
require 'pry/command_set'
require 'pry/commands'
require 'pry/plugins'
require 'pry/core_extensions'
require 'pry/pry_class'
require 'pry/pry_instance'
require 'pry/cli'
require 'pry/color_printer'
require 'pry/pager'
require 'pry/terminal'
require 'pry/editor'
require 'pry/rubygem'
require "pry/indent"
require "pry/last_exception"
require "pry/prompt"
require "pry/inspector"
require 'pry/object_path'
require 'pry/output'
