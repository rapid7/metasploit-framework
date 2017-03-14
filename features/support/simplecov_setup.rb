# @note this file is loaded in env.rb to setup simplecov using RUBYOPTs for child processes

simplecov_command_name = ENV['SIMPLECOV_COMMAND_NAME']

# will not be set if hook does not run because `bundle install --without coverage`
if simplecov_command_name
  require 'simplecov'

  require 'pathname'

  root = Pathname(__FILE__).expand_path.parent.parent.parent

  SimpleCov.command_name(simplecov_command_name)
  SimpleCov.root(root)
  load root.join('.simplecov')
end
