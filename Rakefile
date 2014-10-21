#!/usr/bin/env rake
require File.expand_path('../config/application', __FILE__)
require 'metasploit/framework/require'

# @note must be before `Metasploit::Framework::Application.load_tasks`
#
# define db rake tasks from activerecord if activerecord is in the bundle.  activerecord could be not in the bundle if
# the user installs with `bundle install --without db`
Metasploit::Framework::Require.optionally_active_record_railtie

Metasploit::Framework::Application.load_tasks

# append action to run after normal spec action
task :spec do
  untested_payloads_pathname = Pathname.new 'log/untested-payloads.log'

  if untested_payloads_pathname.exist?
    $stderr.puts "Untested payload detected.  Add tests to spec/modules/payload_spec.rb for payloads classes composed of the following payload modules:"

    untested_payloads_pathname.open do |f|
      f.each_line do |line|
        $stderr.write "  #{line}"
      end
    end

    exit 1
  end
end