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
		queue_task(Task.new(proc))
	end

	#
	# Add a new task to the queue
	#
	def queue_task(task)
		self.queue.push(task)
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
		self.thread     = Thread.new do
			process_tasks
		end
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
		while(self.processing)
			while(task = self.queue.shift)
				ret = process_task(task)
				case ret
				when :requeue
					self.queue.push(task)
				when :drop, :done
					# Processed or dropped
				end
			end
			select(nil, nil, nil, 0.10)
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

			elog("taskmanager: task #{task.inspect} triggered an exception: #{e.class} #{e}")
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

