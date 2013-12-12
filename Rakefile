require 'bundler/setup'

pathname = Pathname.new(__FILE__)
root = pathname.parent

# add metasploit-framework/lib to load paths so rake files can just require
# files normally without having to use __FILE__ and recalculating root and the
# path to lib
lib_pathname = root.join('lib')
$LOAD_PATH.unshift(lib_pathname.to_s)

#
# load rake files like a rails engine
#

rakefile_glob = root.join('lib', 'tasks', '**', '*.rake').to_path

Dir.glob(rakefile_glob) do |rakefile|
  # Skip database tasks, will load them later if MDM is present
  next if rakefile =~ /database\.rake$/
  load rakefile
end

print_without = false

begin
  require 'parallel_tests/tasks'
rescue LoadError
  puts "parallel_tests no in bundle, so can't set up parallel tasks.  " \
       "To run specs in parallel ensure to install the development and test groups"

  print_without = true
end

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

# Require yard before loading metasploit_data_models rake tasks as the yard tasks won't be defined if
# YARD is not defined when yard.rake is loaded.
begin
  require 'yard'
rescue LoadError
	puts "yard not in bundle, so can't set up yard tasks.  " \
	     "To generate documentation ensure to install the documentation group."

	print_without = true
else
  begin
    require 'metasploit/model'
  rescue LoadError
    puts "metasploit-model not in bundle, so can't set up yard tasks.  " \
        "To generate documentation ensure to install the development group."

    print_without = true
  else
    metasploit_model_task_glob = Metasploit::Model.root.join(
        'lib',
        'tasks',
        '**',
        '*.rake'
    ).to_s

    # include tasks from metasploit-model, such as `rake yard`.
    # metasploit-framework specific yard options are in .yardopts
    Dir.glob(metasploit_model_task_glob) do |path|
      load path
    end
  end
end

begin
	require 'metasploit_data_models'
rescue LoadError
	puts "metasploit_data_models not in bundle, so can't set up db tasks.  " \
	     "To run database tasks, ensure to install the db bundler group."

	print_without = true
else
	load 'lib/tasks/database.rake'
end

if print_without
	puts "Bundle currently installed " \
	     "'--without #{Bundler.settings.without.join(' ')}'."
	puts "To clear the without option do `bundle install --without ''` " \
	     "(the --without flag with an empty string) or " \
	     "`rm -rf .bundle` to remove the .bundle/config manually and " \
	     "then `bundle install`"
end
