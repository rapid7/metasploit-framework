Feature: Spork Debugger integration
  As a developer
  I want to invoke the debugger my specs within Spork
  In order to drill in and figure out what's wrong

  Scenario: Invoking the debugger via 'debugger'
    Given a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'spork'
      require 'spork/ext/ruby-debug'

      Spork.prefork { require 'rspec' }
      Spork.each_run { }
      """
    And a file named "spec/debugger_spec.rb" with:
      """
      require 'spec_helper.rb'

      describe "Debugger" do
        it "should debug" do
          2.times do |count|
            @message = "count = #{count}"
            debugger
            @message = nil
          end
          puts "it worked!"
        end
      end
      """

    When I fire up a spork instance with "spork rspec"
    And I run this in the background: rspec --drb spec/debugger_spec.rb

    Then the spork window should output a line containing "Debug Session Started"

    When I type this in the spork window: "e @message"
    Then the spork window should output a line containing "count = 0"

    When I type this in the spork window: "continue"

    When I type this in the spork window: "e @message"
    Then the spork window should output a line containing "count = 1"

    When I type this in the spork window: "continue"

    Then the spork window should output a line containing "Debug Session Terminated"
    And the output should contain "it worked!"

  Scenario: When ruby-debug is already required and started.
      Given a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'spork'
      require 'ruby-debug'
      Debugger.start

      require 'spork/ext/ruby-debug'

      Spork.prefork { require 'rspec' }
      Spork.each_run { }
      """

    And a file named "spec/debugger_spec.rb" with:
      """
      require File.dirname(__FILE__) + '/spec_helper.rb'

      describe "Debugger" do
        it "should debug" do
          @message = "yup"
          debugger
          puts "it worked!"
        end
      end
      """

    When I fire up a spork instance with "spork rspec"
    And I run this in the background: rspec --drb spec/debugger_spec.rb

    Then the spork window should output a line containing "Debug Session Started"

    When I type this in the spork window: "e @message"
    Then the spork window should output a line containing "yup"

    When I type this in the spork window: "continue"

    Then the spork window should output a line containing "Debug Session Terminated"
    And the output should contain "it worked!"

  Scenario: When ruby-debug is invoked during preload
      Given a file named "spec/spec_helper.rb" with:
      """
      require 'rubygems'
      require 'spork'
      require 'spork/ext/ruby-debug'

      STDERR.puts("Spork is ready and listening") # trick out the start spork step to believe spork is ready... naughty, but effective.
      @message = "it worked"
      debugger
      Spork.prefork { require 'rspec' }
      Spork.each_run { }
      """

    When I fire up a spork instance with "spork rspec"
    Then the spork window should output a line containing "spec_helper.rb"
    When I type this in the spork window: "e @message"
    Then the spork window should output a line containing "it worked"
    When I type this in the spork window: "continue"
