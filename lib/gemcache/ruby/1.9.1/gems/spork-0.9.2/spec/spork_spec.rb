require 'spec_helper'

Spork.class_eval do
  def self.reset!
    @state = nil
    @using_spork = false
    @already_ran = nil
    @each_run_procs = nil
  end
end

describe Spork do
  before(:each) do
    Spork.reset!
    @ran = []
  end
  
  def spec_helper_simulator
    Spork.prefork do
      @ran << :prefork
    end
    
    Spork.each_run do
      @ran << :each_run
    end
    @ran
  end
  
  it "only runs the preload block when preforking" do
    Spork.exec_prefork { spec_helper_simulator }
    @ran.should == [:prefork]
  end
  
  it "only runs the each_run block when running" do
    Spork.exec_prefork { spec_helper_simulator }
    @ran.should == [:prefork]
    
    Spork.exec_each_run
    @ran.should == [:prefork, :each_run]
  end
  
  it "runs both blocks when Spork not activated" do
    spec_helper_simulator.should == [:prefork, :each_run]
  end
  
  it "prevents blocks from being ran twice" do
    Spork.exec_prefork { spec_helper_simulator }
    Spork.exec_each_run
    @ran.clear
    Spork.exec_prefork { spec_helper_simulator }
    Spork.exec_each_run
    @ran.should == []
  end
  
  it "runs multiple prefork and each_run blocks at different locations" do
    Spork.prefork { }
    Spork.each_run { }
    spec_helper_simulator.should == [:prefork, :each_run]
  end
  
  it "expands a caller line, preserving the line number" do
    Spork.send(:expanded_caller, "/boo/../yah.rb:31").should == "/yah.rb:31"
  end
  
  describe "#using_spork?" do
    it "returns true if Spork is being used" do
      Spork.using_spork?.should be_false
      Spork.exec_prefork { }
      Spork.using_spork?.should be_true
    end
  end

  describe "#trap_method" do
    before(:each) do
      Spork.exec_prefork { }
      
      Object.class_eval do
        class TrapTest
          def self.output
            @output ||= []
          end
          
          def hello
            TrapTest.output << 'hello'
          end
          
          def goodbye
            TrapTest.output << 'goodbye'
          end
          
          def say_something!
            TrapTest.output << 'something'
          end
        end
      end
      @trap_test = TrapTest.new
    end
    
    after(:each) do
      Object.send(:remove_const, :TrapTest)
    end
    
    it "delays execution of a method until after Spork.exec_each_run is called" do
      Spork.exec_prefork { }
      Spork.trap_method(TrapTest, :hello)
      @trap_test.hello
      @trap_test.goodbye
      Spork.exec_each_run
      TrapTest.output.should == ['goodbye', 'hello']
    end
    
    it "works with methods that have punctuation" do
      Spork.trap_method(TrapTest, :say_something!)
      @trap_test.say_something!
      TrapTest.output.should == []
      Spork.exec_each_run
      TrapTest.output.should == ['something']
    end
  end
  
  describe "#trap_class_method" do
    before(:each) do
      Object.class_eval do
        class TrapTest
          def self.output
            @output ||= []
          end
          
          def self.hello
            output << 'hello'
          end
          
          def self.goodbye
            output << 'goodbye'
          end
        end
      end
    end
    
    after(:each) do
      Object.send(:remove_const, :TrapTest)
    end
    
    it "delays execution of a method until after Spork.exec_each_run is called" do
      Spork.exec_prefork { }
      Spork.trap_class_method(TrapTest, :hello)
      TrapTest.hello
      TrapTest.goodbye
      Spork.exec_each_run
      TrapTest.output.should == ['goodbye', 'hello']
    end
  end
end
