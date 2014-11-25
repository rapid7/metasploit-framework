# @note this file is loaded in env.rb to setup simplecov using RUBYOPTs for child processes

require 'simplecov'

require 'pathname'

root = Pathname(__FILE__).expand_path.parent.parent.parent

SimpleCov.command_name(ENV['SIMPLECOV_COMMAND_NAME'])
SimpleCov.root(root)
load root.join('.simplecov')
