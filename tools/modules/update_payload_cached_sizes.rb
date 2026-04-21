#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script updates the CachedSize constants in payload modules
#

msfbase = __FILE__
msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase)) while File.symlink?(msfbase)

$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$LOAD_PATH.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

gem 'rex-text'
require 'rex'

class StatusReporter
  CLEAR_LINE = "\r\e[2K\r".freeze
  private_constant :CLEAR_LINE

  def print_progress(s)
    return if s.nil?

    @last_progress = s
    print CLEAR_LINE
    print info(s)
    $stdout.flush
  end

  def print_info(s)
    print CLEAR_LINE
    puts info(s)
    print_progress(@last_progress)
  end

  def print_error(s)
    $stderr.print CLEAR_LINE
    $stderr.puts error(s)
    print_progress(@last_progress)
  end

  def finish
    print CLEAR_LINE
    puts
  end

  private

  def info(s)
    "\e[1;36m[*]\e[0m #{s}"
  end

  def error(s)
    "\e[1;33m[!]\e[0m #{s}"
  end
end

# Initialize the simplified framework instance.
framework = Msf::Simple::Framework.create('DisableDatabase' => true)
exceptions = []
reporter = StatusReporter.new
current_payload = 0

# Currently the cached size is stored on stagers, but multiple stages can be associated with one stager
# Maps the stager to the available stages
stagers_to_stages = Hash.new { |hash, key| hash[key] = [] }

modules = []
framework.payloads.each_module do |name, mod|
  modules << [name, mod]
end

total_payloads = modules.length
modules.each do |name, mod|
  next if name =~ /generic/

  current_payload += 1
  reporter.print_progress "Updating single (#{current_payload}/#{total_payloads}) #{name}..."
  mod_inst = framework.payloads.create(name)

  next if mod_inst.is_a?(Msf::Payload::Adapter)

  mod_dependencies = mod_inst.dependencies
  missing_dependencies = mod_dependencies.reject(&:available?)
  if missing_dependencies.any?
    reporter.print_error "Cannot update payload size for #{name} - missing dependencies: #{missing_dependencies.join(',')}"
    next
  end

  if mod_inst.is_a?(Msf::Payload::Stager)
    stagers_to_stages[mod_inst.file_path] << mod_inst
    next
  end

  current_size = mod.dynamic_size? ? ':dynamic' : mod.cached_size
  new_size = Msf::Util::PayloadCachedSize.update_module_cached_size(framework, mod_inst)
  if current_size != new_size
    reporter.print_info "Single Updated: #{name} CacheSize on disk at #{mod.file_path} from #{current_size} to #{new_size}..."
  end
rescue StandardError => e
  reporter.print_error "Caught Error while updating #{name}:\n#{e}\n#{e.backtrace.map { |line| "\t#{line}" }.join("\n")}"
  exceptions << [ e, name ]
end

# Update the metadata on the stager module associated with stages
stager_count = 0
stagers_to_stages.each_value do |stages|
  stager_count += 1
  mod = stages.first
  reporter.print_progress("Updating stager (#{stager_count}/#{stagers_to_stages.length}) #{stages.first.refname}...")
  if mod.dynamic_size?
    current_size = ':dynamic'
  else
    current_size = mod.class.const_defined?('CachedSize') ? mod.class.const_get('CachedSize') : nil
  end
  new_size = Msf::Util::PayloadCachedSize.update_stager_module_cached_size(framework, stages)
  if current_size != new_size
    reporter.print_info "Stager Updated: #{mod.refname} CacheSize on disk at #{mod.file_path} from #{current_size} to #{new_size}..."
  end
rescue StandardError => e
  reporter.print_error "Caught Error while updating #{mod.refname}:\n#{e}\n#{e.backtrace.map { |line| "\t#{line}" }.join("\n")}"
  exceptions << [ e, name ]
end

reporter.finish

exit(1) unless exceptions.empty?
