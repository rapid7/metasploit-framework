begin
  require 'cucumber'
  require 'cucumber/rake/task'


  Cucumber::Rake::Task.new(:features) do |t|
    t.cucumber_opts = 'features --format pretty'
    t.profile = 'default'
  end

  namespace :features do
    Cucumber::Rake::Task.new(:boot) do |t|
      t.profile = 'boot'
    end
  end

rescue LoadError
  task :features do
    puts "cucumber not in bundle, so can't set up feature tasks.  " \
         "To run features ensure to install the development and test groups."
  end
end
