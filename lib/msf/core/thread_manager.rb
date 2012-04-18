require 'msf/core/plugin'

module Msf

###
#
# This class manages the threads spawned by the framework object, this provides some additional
# features over standard ruby threads.
#
###
class ThreadManager < Array

	include Framework::Offspring

	attr_accessor :monitor

	#
	# Initializes the thread manager.
	#
	def initialize(framework)
		self.framework = framework
		self.monitor   = spawn_monitor
	end

	#
	# Spawns a monitor thread for removing dead threads
	#
	def spawn_monitor
		::Thread.new do
			begin

			::Thread.current[:tm_name] = "Thread Monitor"
			::Thread.current[:tm_crit] = true

			while true
				::IO.select(nil, nil, nil, 1.0)
				self.each_index do |i|
					state = self[i].alive? rescue false
					self[i] = nil if not state
				end
				self.delete(nil)
			end

			rescue ::Exception => e
				elog("thread monitor: #{e} #{e.backtrace} source:#{self[:tm_call].inspect}")
			end
		end
	end

	#
	# Spawns a new thread
	#
	def spawn(name, crit, *args, &block)
		t = nil

		if block
			t = ::Thread.new(name, crit, caller, block, *args) do |*argv|
				::Thread.current[:tm_name] = argv.shift.to_s
				::Thread.current[:tm_crit] = argv.shift
				::Thread.current[:tm_call] = argv.shift
				::Thread.current[:tm_time] = Time.now

				begin
					argv.shift.call(*argv)
				rescue ::Exception => e
					elog("thread exception: #{::Thread.current[:tm_name]}  critical=#{::Thread.current[:tm_crit]}  error:#{e.class} #{e} source:#{::Thread.current[:tm_call].inspect}")
					elog("Call Stack\n#{e.backtrace.join("\n")}")
					raise e
				end
				if framework.db and framework.db.active
					::ActiveRecord::Base.connection.close if ActiveRecord::Base.connection
				end				
			end
		else
			t = ::Thread.new(name, crit, caller, *args) do |*argv|
				::Thread.current[:tm_name] = argv.shift
				::Thread.current[:tm_crit] = argv.shift
				::Thread.current[:tm_call] = argv.shift
				::Thread.current[:tm_time] = Time.now
			end
		end

		self << t
		t
	end

	#
	# Registers an existing thread
	#
	def register(t, name, crit)
		t[:tm_name] = name
		t[:tm_crit] = crit
		t[:tm_call] = caller
		t[:tm_time] = Time.now
		self << t
		t
	end

	#
	# Updates an existing thread
	#
	def update(ut, name, crit)
		ti = nil
		self.each_index do |i|
			tt = self[i]
			next if not tt
			if ut.__id__ == tt.__id__
				ti = i
				break
			end
		end

		t = self[ti]
		if not t
			raise RuntimeError, "Thread not found"
		end

		t[:tm_name] = name
		t[:tm_crit] = crit
		t
	end

	#
	# Kills a thread by index
	#
	def kill(idx)
		self[idx].kill rescue false
	end

end

end
