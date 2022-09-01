#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# This user interface provides users with a command console interface to the
# framework.
#

require 'pathname'
begin

  # Silences warnings as they only serve to confuse end users
  if defined?(Warning) && Warning.respond_to?(:[]=)
    Warning[:deprecated] = false
  end

  # @see https://github.com/rails/rails/blob/v3.2.17/railties/lib/rails/generators/rails/app/templates/script/rails#L3-L5
  require Pathname.new(__FILE__).realpath.expand_path.parent.join('config', 'boot')
  require 'msfenv'
  require 'metasploit/framework/profiler'
  require 'metasploit/framework/command/console'

  Metasploit::Framework::Profiler.start
  Metasploit::Framework::Command::Console.start
rescue Interrupt
  puts "\nAborting..."
  exit(1)
end
