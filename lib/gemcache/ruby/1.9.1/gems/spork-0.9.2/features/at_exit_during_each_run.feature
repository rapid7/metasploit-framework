Feature: At exit during each run
  In order to make sure at_exit hooks defined during the run get called
  I want to override kernel #at_exit

  Scenario: at exit

    Given a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'rspec'
      Spork.prefork do
        puts "loading"
        at_exit { puts "prefork at_exit called" }
      end

      Spork.each_run do
        puts "running"
        at_exit { printf "first " }
        at_exit { printf "second " }
      end

      """

    And a file named "spec/did_it_work_spec.rb" with:
      """
      require 'spec_helper'
      describe "Did it work?" do
        it "checks to see if all worked" do
          puts "ran specs"
        end
      end
      """
    When I fire up a spork instance with "spork rspec"
    And I run rspec --drb spec/did_it_work_spec.rb
    Then the output should contain "second first"
    Then the output should not contain "prefork at_exit called"
