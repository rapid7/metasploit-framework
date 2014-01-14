# -*- coding:binary -*-

require 'msf/core'
require 'msf/core/task_manager'

describe Msf::TaskManager do

  let(:framework) do
    Msf::Framework.new
  end

  let(:tm) do
    Msf::TaskManager.new(framework)
  end

  it "should have attributes" do
    tm.should respond_to("processing")
    tm.should respond_to("queue")
    tm.should respond_to("thread")
    tm.should respond_to("framework")
    tm.should respond_to("processing=")
    tm.should respond_to("queue=")
    tm.should respond_to("thread=")
    tm.should respond_to("framework=")
  end

  it "should initialize with an empty queue" do
    tm.queue.length.should == 0
    tm.backlog.should == 0
    tm.backlog.should == tm.queue.length
  end

  it "should add items to the queue and process them" do
    tm.queue_proc(Proc.new{ })
    tm.backlog.should == 1
    t = Msf::TaskManager::Task.new(Proc.new { })
    tm.queue_task(t)
    tm.backlog.should == 2
    tm.start
    t.wait
    tm.backlog.should == 0
  end

  it "should add items to the queue and flush them" do
    tm.queue_proc(Proc.new{ })
    tm.backlog.should == 1
    tm.queue_proc(Proc.new{ })
    tm.backlog.should == 2
    tm.flush
    tm.backlog.should == 0
  end

  it "should start and stop" do
    t = Msf::TaskManager::Task.new(Proc.new { })
    tm.queue_task(t)
    tm.backlog.should == 1
    tm.start
    t.wait
    tm.backlog.should == 0
    tm.stop
    1.upto 100 do |cnt|
      tm.queue_proc(Proc.new{ })
      tm.backlog.should == cnt
    end
    t = Msf::TaskManager::Task.new(Proc.new { })
    tm.queue_task(t)
    tm.start
    t.wait
    tm.backlog.should == 0
  end

  it "should handle task timeouts" do
    t = Msf::TaskManager::Task.new(Proc.new { sleep(30) })
    t.timeout = 0.1

    tm.start
    tm.queue_task(t)
    t.wait

    t.status.should == :timeout
    t.duration.should <= 5.0
  end

  it "should handle task exceptions" do
    t = Msf::TaskManager::Task.new(Proc.new { asdf1234() })
    tm.start
    tm.queue_task(t)
    t.wait
    t.status.should == :dropped
    t.exception.class.should == ::NoMethodError

    t = Msf::TaskManager::Task.new(Proc.new { eval "'" })
    tm.queue_task(t)
    t.wait
    t.status.should == :dropped
    t.exception.should be_a ::SyntaxError
  end
end

