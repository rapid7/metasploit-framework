Feature: Unknown app frameworks
  To increase to usefulness of Spork 
  Spork will work with unknown (or no) application frameworks

  Scenario: Unsporked spec_helper
  
    Given a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'spec'
      """
    When I run spork
    Then the error output should contain "Using RSpec"
    Then the error output should match /You must bootstrap .+spec\/spec_helper\.rb to continue/
  
  Scenario: Sporked spec_helper
    Given a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'spork'
      
      Spork.prefork do
        require 'spec'
      end
      
      Spork.each_run do
        $each_run
      end
      """
    And a file named "spec/did_it_work_spec.rb" with:
      """
      describe "Did it work?" do
        it "checks to see if all worked" do
          Spork.state.should == :using_spork
          puts "Specs successfully run within spork"
        end
      end
      """
    When I fire up a spork instance with "spork rspec"
    And I run spec --drb spec/did_it_work_spec.rb 
    Then the output should contain "Specs successfully run within spork"
  