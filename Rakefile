require 'bundler/setup'

require 'metasploit_data_models'

#
# load rake files like a rails engine
#

pathname = Pathname.new(__FILE__)
root = pathname.parent
rakefile_glob = root.join('lib', 'tasks', '**', '*.rake').to_path

Dir.glob(rakefile_glob) do |rakefile|
  load rakefile
end

print_without = false

begin
	require 'rspec/core/rake_task'
rescue LoadError
	puts "rspec not in bundle, so can't set up spec tasks.  " \
	     "To run specs ensure to install the development and test groups."

	print_without = true
else
	RSpec::Core::RakeTask.new(:spec => 'db:test:prepare')

	task :default => :spec
end

begin
  require 'yard'
rescue LoadError
	puts "yard not in bundle, so can't set up yard tasks.  " \
	     "To generate documentation ensure to install the development group."

	print_without = true
end

metasploit_data_models_task_glob = MetasploitDataModels.root.join(
		'lib',
		'tasks',
		'**',
		'*.rake'
).to_s

# include tasks from metasplioit_data_models, such as `rake yard`.
# metasploit-framework specific yard options are in .yardopts
Dir.glob(metasploit_data_models_task_glob) do |path|
	load path
end

if print_without
	puts "Bundle currently installed " \
	     "'--without #{Bundler.settings.without.join(' ')}'."
	puts "To clear the without option do `bundle install --without ''` " \
	     "(the --without flag with an empty string) or " \
	     "`rm -rf .bundle` to remove the .bundle/config manually and " \
	     "then `bundle install`"
end
