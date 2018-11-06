module PatchFinder
  class ThreadPool

    attr_accessor :mutex

    # Initializes the pool.
    #
    # @param size [Fixnum] Max number of threads to be running at the same time.
    # @return [void]
    def initialize(size)
      @size = size
      @mutex = Mutex.new
      @jobs = Queue.new
      @pool = Array.new(@size) do |i|
        Thread.new do
          Thread.current[:id] = i
          catch(:exit) do
            loop do
              job, args = @jobs.pop
              job.call(*args)
            end
          end
        end
      end
    end

    # Adds a job to the queue.
    #
    # @param args [Array] Arguments.
    # @param block [Proc] Code.
    def schedule(*args, &block)
      @jobs << [block, args]
    end

    # Shuts down all the jobs.
    #
    # @return [void]
    def shutdown
      @size.times do
        schedule { throw :exit }
      end

      @pool.map(&:join)
    end

    # Returns whether there's anything in the queue left.
    #
    # @return [boolean]
    def eop?
      @jobs.empty?
    end

    # Terminates all threads
    #
    # @return [void]
    def cleanup
      @jobs.clear
      @pool.map(&:kill)
    end

  end
end

=begin
 
 Nothings that might not work so great in the pool:
 * Timeout
  
=end
