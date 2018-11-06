# encoding: US-ASCII

# Stub file to conform gem name (rb-readline)
# It forces require of bundled readline instead of any already existing
# in your Ruby installation. It will avoid any possible warning caused
# by double require.
# Remove any Readline module that has been defined so far. This is primarily to
# catch cases where GNU Readline has already been required. Unfortunately, it
# is not without problems - any calls to methods like Readline.completion_proc
# will need to be re-made.
if (defined? Readline) && (! defined? RbReadline)
  if $DEBUG
    STDERR.puts "Removing old Readline module - redefined by rb-readline."
  end
  Object.send(:remove_const, :Readline)
  require File.join(File.dirname(__FILE__), 'readline')
end

