Feature: Rails Integration
  To get a developer up and running quickly
  Spork automatically integrates with rails
  Providing default hooks and behaviors

  Background: Rails App with RSpec and Spork
    Given I am in a fresh rails project named "test_rails_project"
    And a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'spork'

      Spork.prefork do
        # Loading more in this block will cause your specs to run faster. However, 
        # if you change any configuration or code from libraries loaded here, you'll
        # need to restart spork for it take effect.
        require File.dirname(__FILE__) + '/../config/environment.rb'
        require 'rspec'
        require 'rspec/rails'
        
        #### this is for this test only #######
        $loaded_stuff << 'prefork block' ######
        #######################################
      end

      Spork.each_run do
        # This code will be run each time you run your specs.
        
        #### this is for this test only #######
        $loaded_stuff << 'each_run block' #####
        #######################################
      end
      """
    And the application has a model, observer, route, and application helper
  Scenario: Analyzing files were preloaded
    When I run spork --diagnose
    Then the output should not contain "user_observer.rb"
    Then the output should not contain "user.rb"
    Then the output should not contain "app/controllers/application.rb"
    Then the output should not contain "app/controllers/application_controller.rb"
    Then the output should not contain "app/controllers/application_helper.rb"
    # Then the output should not contain "config/routes.rb"
  
  Scenario: Running spork with a rails app and observers
    Given a file named "spec/did_it_work_spec.rb" with:
    """
    require 'spec_helper'
    describe "Did it work?" do
      it "checks to see if all worked" do
        Spork.using_spork?.should == true
        (Rails.respond_to?(:logger) ? Rails.logger : ActionController::Base.logger).info "hey there"
        $loaded_stuff.should include('ActiveRecord::Base.establish_connection')
        $loaded_stuff.should include('User')
        $loaded_stuff.should include('UserObserver')
        $loaded_stuff.should include('ApplicationHelper')
        $loaded_stuff.should include('config/routes.rb')
        $loaded_stuff.should include('each_run block')
        $loaded_stuff.should include('prefork block')
        puts "Specs successfully run within spork, and all initialization files were loaded"
      end
    end
    """
    When I fire up a spork instance with "spork rspec"
    And I run rspec --drb spec/did_it_work_spec.rb
    Then the error output should be empty
    And the output should contain "Specs successfully run within spork, and all initialization files were loaded"
    And the file "log/test.log" should include "hey there"


  Scenario: Running spork with a rails app and a non-standard port
    Given a file named "spec/did_it_work_spec.rb" with:
    """
    describe "Did it work?" do
      it "checks to see if all worked" do
        Spork.using_spork?.should == true
        (Rails.respond_to?(:logger) ? Rails.logger : ActionController::Base.logger).info "hey there"
        $loaded_stuff.should include('ActiveRecord::Base.establish_connection')
        $loaded_stuff.should include('User')
        $loaded_stuff.should include('UserObserver')
        $loaded_stuff.should include('ApplicationHelper')
        $loaded_stuff.should include('config/routes.rb')
        $loaded_stuff.should include('each_run block')
        $loaded_stuff.should include('prefork block')
        puts "Specs successfully run within spork, and all initialization files were loaded"
      end
    end
    """
    When I fire up a spork instance with "spork rspec --port 7000"
    And I run rspec --drb --drb-port 7000 spec/did_it_work_spec.rb
    Then the error output should be empty
    And the output should contain "Specs successfully run within spork, and all initialization files were loaded"
    And the file "log/test.log" should include "hey there"
