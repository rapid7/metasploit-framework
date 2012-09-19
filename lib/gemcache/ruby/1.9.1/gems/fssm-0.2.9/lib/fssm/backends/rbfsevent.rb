module FSSM::Backends
  class RBFSEvent
    def initialize
      @handlers = []
    end

    def add_handler(handler, preload=true)
      @handlers << handler
      handler.refresh(nil, true) if preload
    end

    def run
      begin
        @fsevent = FSEvent.new
        @fsevent.watch(temporary_multipath_hack) do |paths|
          paths.each do |path|
            temporary_multipath_handler(path)
          end
        end
        @fsevent.run
      rescue Interrupt
        @fsevent.stop
      end
    end

    def temporary_multipath_handler(path)
      @handlers.each do |handler|
        handler_path = File.join(handler.path.to_s, "")
        if path.start_with?(handler_path)
          handler.refresh(path)
          break
        end
      end
    end

    def temporary_multipath_hack
      @handlers = @handlers.sort {|x,y| y.path.to_pathname.segments.length <=> x.path.to_pathname.segments.length}
      return @handlers.map {|handler| handler.path.to_s}
    end

  end
end
