#!/usr/bin/env rake
require File.expand_path('../config/application', __FILE__)
require 'metasploit/framework/require'
require 'metasploit/framework/spec/untested_payloads'

Metasploit::Framework::Application.load_tasks
Metasploit::Framework::Spec::Constants.define_task
Metasploit::Framework::Spec::Threads::Suite.define_task
Metasploit::Framework::Spec::UntestedPayloads.define_task
