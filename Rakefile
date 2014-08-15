#!/usr/bin/env rake
require File.expand_path('../config/application', __FILE__)
require 'metasploit/framework/require'

# @note must be before `Metasploit::Framework::Application.load_tasks`
#
# define db rake tasks from activerecord if activerecord is in the bundle.  activerecord could be not in the bundle if
# the user installs with `bundle install --without db`
Metasploit::Framework::Require.optionally_active_record_railtie

Metasploit::Framework::Application.load_tasks
