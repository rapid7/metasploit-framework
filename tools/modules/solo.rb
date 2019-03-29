#!/usr/bin/env ruby

module Msf
  module Modules
  end
end

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msf/core/modules/external'

require 'json'

module_path = ARGV.shift

# Usage when we don't have a module name
def usage(mod='MODULE_FILE', name='Run a module outside of Metasploit Framework')
  $stderr.puts "Usage: solo.rb #{mod} [OPTIONS] [ACTION]"
  $stderr.puts name
end

def log_output(m)
  message = m.params['message']

  sigil = case m.params['level']
  when 'error', 'warning'
    '!'
  when 'good'
    '+'
  else
    '*'
  end

  $stderr.puts "[#{sigil}] #{message}"
end

def process_report(m)
  puts "[+] Found #{m.params['type']}: #{JSON.generate m.params['data']}"
end

if !module_path || module_path[0] == '-'
  usage
else
  mod = Msf::Modules::External.new module_path
  args, method = Msf::Modules::External::CLI.parse_options mod

  success = mod.exec(method: method, args: args) do |m|
    begin
      case m.method
      when :message
        log_output(m)
      when :report
        process_report(m)
      when :reply
        puts m.params['return']
      end
    rescue Interrupt => e
      abort 'Exiting...'
    rescue Exception => e
      abort "Encountered an error: #{e.message}"
    end
  end

  abort 'Module exited abnormally' if !success
end
