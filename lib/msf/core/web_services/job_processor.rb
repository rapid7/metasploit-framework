require 'singleton'

class JobProcessor
  include Singleton

  def submit_job(job_args, &job)
    @job_queue << JobWraper.new(job_args, &job)
  end

  private

  def initialize
    @job_queue = Queue.new()
    start_processor_thread()
  end

  def start_processor_thread()
    Thread.new {
      loop do
        wrapper = @job_queue.pop()
        begin
          wrapper.job.call(wrapper.job_args)
        rescue => e
          print_error "Error executing job #{e.message}", e
        end
      end
    }
  end

  class JobWraper
    attr_reader :job
    attr_reader :job_args

    def initialize(job_args, &job)
      @job_args = job_args
      @job = job
    end
  end
end