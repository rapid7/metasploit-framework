# -*- coding: binary -*-
module Msf

###
#
# This class provides a task manager
#
###

class TaskManager

  class Task
    attr_accessor :timeout
    attr_accessor :created
    attr_accessor :completed
    attr_accessor :status
    attr_accessor :proc
    attr_accessor :source
    attr_accessor :exception

    #
    # Create a new task
    #
    def initialize(proc,timeout=nil)
      self.proc    = proc
      self.status  = :new
      self.created = Time.now
      self.timeout = timeout
      self.source  = caller
    end

    #
    # Task duration in seconds (float)
    #
    def duration
      etime = self.completed || Time.now
      etime.to_f - self.created.to_f
    end

    def wait
      while self.status == :new
        Rex.sleep(0.10)
      end
      return self.status
    end

    #
    # Run the associated proc
    #
    def run(*args)
      self.proc.call(*args) if self.proc
    end

  end


  attr_accessor :processing
  attr_accessor :queue
  attr_accessor :thread
  attr_accessor :framework

  #
  # Create a new TaskManager
  #
  def initialize(framework)
    self.framework = framework
    self.flush
  end

  #
  # Add a new task via proc
  #
  def queue_proc(proc)
    task = Task.new(proc)
    queue_task(task)
    return task
  end

  #
  # Add a new task to the queue unless we are called
  # by the queue thread itself.
  #
  def queue_task(task)
    if Thread.current[:task_manager]
      process_task(task)
    else
      self.queue.push(task)
    end
  end

  #
  # Flush the queue
  #
  def flush
    self.queue = []
  end

  #
  # Stop processing events
  #
  def stop
    return if not self.thread
    self.processing = false
    self.thread.join
    self.thread = nil
  end

  #
  # Forcefully kill the processing thread
  #
  def kill
    return if not self.thread
    self.processing = false
    self.thread.kill
    self.thread = nil
  end

  #
  # Start processing tasks
  #
  def start
    return if self.thread
    self.processing = true
    self.thread     = framework.threads.spawn("TaskManager", true) do
      begin
        process_tasks
      rescue ::Exception => e
        elog("taskmanager: process_tasks exception: #{e.class} #{e} #{e.backtrace}")
        retry
      end
    end

    # Mark this thread as the task manager
    self.thread[:task_manager] = true

    # Return the thread object to the caller
    self.thread
  end

  #
  # Restart the task processor
  #
  def restart
    stop
    start
  end

  #
  # Retrieve the number of tasks in the queue
  #
  def backlog
    self.queue.length
  end

  #
  # Process the actual queue
  #
  def process_tasks
    spin  = 50
    ltask = nil

    while(self.processing)
      cnt = 0
      while(task = self.queue.shift)
        stime = Time.now.to_f
        ret = process_task(task)
        etime = Time.now.to_f

        case ret
        when :requeue
          self.queue.push(task)
        when :drop, :done
          # Processed or dropped
        end
        cnt += 1

        ltask = task
      end

      spin = (cnt == 0) ? (spin + 1) : 0

      if spin > 10
        Rex.sleep(0.25)
      end

    end
    self.thread = nil
  end

  #
  # Process a specific task from the queue
  #
  def process_task(task)
    begin
      if(task.timeout)
        ::Timeout.timeout(task.timeout) do
          task.run(self, task)
        end
      else
        task.run(self, task)
      end
    rescue ::ThreadError
      # Ignore these (caused by a return inside of the proc)
    rescue ::Exception => e

      if(e.class == ::Timeout::Error)
        elog("taskmanager: task #{task.inspect} timed out after #{task.timeout} seconds")
        task.status = :timeout
        task.completed = Time.now
        return :drop
      end

      elog("taskmanager: task triggered an exception: #{e.class} #{e}")
      elog("taskmanager: task proc: #{task.proc.inspect} ")
      elog("taskmanager: task Call stack: \n#{task.source.join("\n")} ")
      dlog("Call stack:\n#{$@.join("\n")}")

      task.status    = :dropped
      task.exception = e
      return :drop

    end
    task.status = :done
    task.completed = Time.now
    return :done
  end

  def log_error(msg)
    elog(msg, 'core')
  end

  def log_debug(msg)
    dlog(msg, 'core')
  end

end
end

