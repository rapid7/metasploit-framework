Given /^I am in a fresh rails project named "(.+)"$/ do |folder_name|
  @current_dir = SporkWorld::SANDBOX_DIR
  # version_argument = ENV['RAILS_VERSION'] ? "_#{ENV['RAILS_VERSION']}_" : nil
  # run("#{SporkWorld::RUBY_BINARY} #{%x{which rails}.chomp} #{folder_name}")
  run(["rails", "new", folder_name].compact * " ")

  if last_exit_status != 0
    puts "Couldn't generate project.  Output:\nSTDERR:\n-------\n#{last_stderr}\n------\n\nSTDOUT:\n-------\n#{last_stdout}\n\n"
    last_exit_status.should == 0
  end
  @current_dir = File.join(File.join(SporkWorld::SANDBOX_DIR, folder_name))
  in_current_dir do
    FileUtils.ln_sf(ENV["BUNDLE_GEMFILE"], "Gemfile")
    FileUtils.ln_sf(ENV["BUNDLE_GEMFILE"] + ".lock", "Gemfile.lock")
    FileUtils.ln_sf(File.dirname(ENV["BUNDLE_GEMFILE"]) + "/.bundle", ".bundle")
  end
end


Given "the application has a model, observer, route, and application helper" do
  Given 'the following code appears in "config/application.rb" after /^end/:',
    """
    ActiveRecord::Base.observers = [:user_observer]
    """
  Given 'a file named "app/models/user.rb" with:',
    """
    class User < ActiveRecord::Base
      $loaded_stuff << 'User'
    end
    """
  Given 'a file named "app/models/user_observer.rb" with:',
    """
    class UserObserver < ActiveRecord::Observer
      $loaded_stuff << 'UserObserver'
    end
    """
  Given 'a file named "app/helpers/application_helper.rb" with:',
    """
    module ApplicationHelper
      $loaded_stuff << 'ApplicationHelper'
    end
    """
  Given 'the following code appears in "config/environment.rb" after /Rails::Initializer.run/:',
    """
      config.active_record.observers = :user_observer
    """
  Given 'the following code appears in "config/routes.rb" after /^end/:',
    """
      $loaded_stuff << 'config/routes.rb'
    """
  Given 'a file named "config/initializers/initialize_loaded_stuff.rb" with:',
    """
    $loaded_stuff ||= []
    """
  Given 'a file named "config/initializers/log_establish_connection_calls.rb" with:',
    """
    class ActiveRecord::Base
      class << self
        def establish_connection_with_load_logging(*args)
          $loaded_stuff << 'ActiveRecord::Base.establish_connection'
          establish_connection_without_load_logging(*args)
        end
        alias_method_chain :establish_connection, :load_logging
      end
    end
    """
end
