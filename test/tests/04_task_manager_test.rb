$:.push("../../lib")

require 'testbase'
require 'msf/core/task_manager'

describe Msf::TaskManager do
	it "should have attributes" do
		tm = Msf::TaskManager.new($msf)
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
		tm = Msf::TaskManager.new($msf)
		tm.queue.length.should == 0
		tm.backlog.should == 0
		tm.backlog.should == tm.queue.length
	end

	it "should add items to the queue and process them" do
		tm = Msf::TaskManager.new($msf)
		tm.queue_proc(Proc.new{ })
		tm.backlog.should == 1
		tm.queue_proc(Proc.new{ })
		tm.backlog.should == 2
		tm.start
		sleep(0.5)
		tm.backlog.should == 0
	end

	it "should add items to the queue and flush them" do
		tm = Msf::TaskManager.new($msf)
		tm.queue_proc(Proc.new{ })
		tm.backlog.should == 1
		tm.queue_proc(Proc.new{ })
		tm.backlog.should == 2
		tm.flush
		tm.backlog.should == 0
	end

	it "should start and stop" do
		tm = Msf::TaskManager.new($msf)
		tm.queue_proc(Proc.new{ })
		tm.backlog.should == 1
		tm.start
		sleep(0.5)
		tm.backlog.should == 0
		tm.stop
		tm.queue_proc(Proc.new{ })
		tm.backlog.should == 1
		sleep(0.5)
		tm.queue_proc(Proc.new{ })
		tm.backlog.should == 2
		tm.start
		sleep(0.5)
		tm.backlog.should == 0
	end

	it "should handle task timeouts" do
		tm = Msf::TaskManager.new($msf)
		t  = Msf::TaskManager::Task.new(Proc.new { sleep(30) })
		t.timeout = 0.1

		tm.start
		tm.queue_task(t)
		sleep(0.5)

		t.status.should == :timeout
		t.duration.should <= 1.0
	end

	it "should handle task exceptions" do
		tm = Msf::TaskManager.new($msf)
		t  = Msf::TaskManager::Task.new(Proc.new { asdf1234() })

		tm.start
		tm.queue_task(t)
		sleep(0.5)

		t.status.should == :dropped
		t.exception.class.should == ::NoMethodError
	end

	it "should handle a bad proc return" do
		tm = Msf::TaskManager.new($msf)
		t  = Msf::TaskManager::Task.new(Proc.new { return 12345 })

		tm.start
		tm.queue_task(t)
		sleep(0.5)

		t.status.should == :done
		t.exception.should == nil
	end
end

