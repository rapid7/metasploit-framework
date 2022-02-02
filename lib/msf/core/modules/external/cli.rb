# -*- coding: binary -*-
# CLI for interaction with modules outside of msfconsole

require 'optparse'

module Msf::Modules::External::CLI
  def self.parse_options(mod)
    action = 'run'
    actions = ['run'] + mod.meta['capabilities']
    args = mod.meta['options'].reduce({}) do |defaults, (n, opt)|
      if opt['default'].nil?
        if opt['required']
          defaults
        else
          defaults[n] = nil
          defaults
        end
      else
        defaults[n] = opt['default']
        defaults
      end
    end

    op = OptionParser.new do |opts|
      if $0 != mod.path
        opts.banner = "Usage: #{$0} #{mod.path} [OPTIONS] [ACTION]"
      end
      opts.separator ""

      opts.separator mod.meta['description']
      opts.separator ""

      opts.separator "Postitional arguments:"
      opts.separator "  ACTION:    The action to take (#{actions.inspect})"
      opts.separator ""

      opts.separator "Required arguments:"
      make_options opts, args, mod.meta['options'].select {|n, o| o['required'] && o['default'].nil?}
      opts.separator ""

      opts.separator "Optional arguments:"
      make_options opts, args, mod.meta['options'].select {|n, o| !o['required'] || !o['default'].nil?}

      opts.on '-h', '--help', 'Prints this help' do
        $stderr.puts opts
        exit
      end
    end

    begin
      extra = op.permute *ARGV
      # If no extra args are given we use the default action
      if extra.length == 1
        action = extra.shift
      elsif extra.length > 1
        action = extra.shift
        $stderr.puts "WARNING: unrecognized arguments #{extra.inspect}"
      end
    rescue OptionParser::InvalidArgument => e
      $stderr.puts e.message
      abort
    rescue OptionParser::MissingArgument => e
      $stderr.puts e.message
      abort
    end

    required = mod.meta['options'].select {|_, o| o['required']}.map {|n, _| n}.sort

    # Were we run with any non-module options if we need them?
    if args.empty? && !required.empty?
      $stderr.puts op
      exit
    # Did someone forget to add some options we need?
    elsif (args.keys & required).sort != required
      missing = required - (args.keys & required)
      abort "Missing required option(s): #{missing.map {|o| '--' + o}.join ', '}"
    end

    unless action == 'run' || mod.meta['capabilities'].include?(action)
      $stderr.puts "Invalid ACTION choice #{action.inspect} (choose from #{actions.inspect})"
      abort
    end

    action =
      case action
      when 'run'; :run
      when 'soft_check'; :soft_check
      when 'hard_check'; :hard_check
      end
    [args, action]
  end

  def self.choose_type(t)
    if t == 'int' or t == 'port'
      Integer
    elsif t == 'float'
      Float
    elsif t.match /range$/
      Array
    else # XXX TODO add validation for addresses and other MSF option types
      String
    end
  end

  def self.make_options(parser, out, args)
    args.each do |n, opt|
      name = n.tr('_', '-')
      desc = if opt['default']
        "#{opt['description']}, (default: #{opt['default']})"
      else
        opt['description']
      end
      parser.on "--#{name} #{n.upcase}", choose_type(opt['type']), desc do |arg|
        out[n] = arg
      end
    end
  end
end
