Feature: Rails Delayed Work arounds
  To allow a rails developer to update as many parts of his application as possible without needing to restart Spork
  Spork automatically tells rails to delay loading certain parts of the application until after the fork occurs

  Background: Rails App with RSpec and Spork

    Given I am in a fresh rails project named "test_rails_project"
    And a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'spork'
      require 'spork/ext/ruby-debug'

      Spork.prefork do
        require File.dirname(__FILE__) + '/../config/environment.rb'
        require 'rspec'
        require 'rspec/rails'
      end

      Spork.each_run do
      end
      """
    And the application has a model, observer, route, and application helper

    Given the following code appears in "config/routes.rb" after /routes\.draw/:
      """
        resources :users
      """
    Given a file named "app/helpers/application_helper.rb" with:
      """
      require 'reverseatron'
      module ApplicationHelper
        include Reverseatron
      end
      """
    Given a file named "lib/reverseatron.rb" with:
      """
      module Reverseatron
        def reverse_text(txt)
          txt.reverse
        end
      end
      """
    Given a file named "app/controllers/users_controller.rb" with:
      """
      class UsersController < ApplicationController
        $loaded_stuff << 'UsersController'
        def index
          @users = []
        end
      end
      """
    Given a file named "app/helpers/misc_helper.rb" with:
      """
      module MiscHelper
        def misc_helper_method
          'hello miscellaneous'
        end
      end
      """
    Given a file named "app/helpers/users_helper.rb" with:
      """
      module UsersHelper
      end
      """
    Given a file named "app/views/users/index.html.erb" with:
      """
        Original View
      """
  Scenario: respecting custom autoload paths
    Given the following code appears in "config/application.rb" after /class Application < Rails::Application/:
      """
        config.autoload_paths << 'app/models/non_standard'
      """

    And a file named "app/models/non_standard/boogie.rb" with:
      """
        class Boogie
          def boogie
            'Boogie Robots!'
          end
        end
      """
    And a file named "spec/models/non_standard/boogie_spec.rb" with:
      """
        describe Boogie do
          it 'knows how to boogie' do
            Boogie.new.boogie.should include('Boogie')
            puts 'BOOGIE!!!'
          end
        end
      """
    When I fire up a spork instance with "spork rspec"
    And I run rspec --drb spec/models/non_standard/boogie_spec.rb
    Then the output should contain "BOOGIE!!!"

  Scenario: within a view rendered by a controller, calling helper methods from an included module in ApplicationHelper
    Given a file named "spec/controllers/users_controller_spec.rb" with:
      """
      require "spec_helper"
      describe UsersController do
        render_views
        it "renders a page, using a method inherited from ApplicationController" do
          get :index
          response.body.should_not include('Original View')
          puts "Views are not being cached when rendering from a controller"

          response.body.should include('listing users')
          puts "Controller stack is functioning when rendering from a controller"

          response.body.should include('hello miscellaneous')
          puts "All helper modules were included when rendering from a controller"
        end
      end
      """
    Given a file named "spec/views/index.html.erb_spec.rb" with:
      """
      require "spec_helper"
      describe "/users/index.html.erb" do

        it "renders the view" do
          render
          rendered.should_not include('Original View')
          puts "Views are not being cached when rendering directly"

          rendered.should include('listing users')
          puts "Controller stack is functioning when rendering directly"

          rendered.should include('hello miscellaneous')
          puts "All helper modules were included when rendering directly"
        end
      end
      """
    When I fire up a spork instance with "spork rspec"
    And the contents of "app/views/users/index.html.erb" are changed to:
      """
      <%= reverse_text('listing users'.reverse) %>
      <%= misc_helper_method rescue nil %>
      <p>Here is a list of users</p>
      """
      
    And I run rspec --drb spec/controllers/users_controller_spec.rb
    Then the output should contain "Controller stack is functioning when rendering from a controller"
    And  the output should contain "Views are not being cached when rendering from a controller"
    And  the output should contain "All helper modules were included when rendering from a controller"

    When I run rspec --drb spec/views/index.html.erb_spec.rb
    Then the output should contain "Controller stack is functioning when rendering directly"
    And  the output should contain "Views are not being cached when rendering directly"
    And  the output should contain "All helper modules were included when rendering directly"

    Given the contents of "app/helpers/application_helper.rb" are changed to:
      """
      module ApplicationHelper
        def make_it_loud(message)
          message.upcase
        end
      end
      """
    And the contents of "app/views/users/index.html.erb" are changed to:
      """
      <%= make_it_loud('listing users') %>
      """
    And the contents of "spec/controllers/users_controller_spec.rb" are changed to:
      """
      require "spec_helper"
      describe UsersController do
        render_views
        it "renders a page, using a method inherited from ApplicationController" do
          get :index
          response.body.should include('LISTING USERS')
          puts "Helpers aren't being cached"
        end
      end
      """
    When I run rspec --drb spec/controllers/users_controller_spec.rb
    Then the output should contain "Helpers aren't being cached"
