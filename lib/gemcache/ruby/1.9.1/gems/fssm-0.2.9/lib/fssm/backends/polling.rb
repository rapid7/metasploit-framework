module FSSM::Backends
  class Polling
    def initialize(options={})
      @handlers = []
      @latency  = options[:latency] || 1.5
    end

    def add_handler(handler, preload=true)
      handler.refresh(nil, true) if preload
      @handlers << handler
    end

    def run
      begin
        loop do
          start = Time.now.to_f
          @handlers.each { |handler| handler.refresh }
          nap_time = @latency - (Time.now.to_f - start)
          sleep nap_time if nap_time > 0
        end
      rescue Interrupt
      end
    end
  end
end
