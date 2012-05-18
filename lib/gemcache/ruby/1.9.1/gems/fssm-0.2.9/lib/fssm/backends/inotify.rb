module FSSM::Backends
  class Inotify
    def initialize
      @notifier = INotify::Notifier.new
    end

    def add_handler(handler, preload=true)
      @notifier.watch(handler.path.to_s, :recursive, :attrib, :close_write, :create,
                      :delete, :delete_self, :moved_from, :moved_to, :move_self) do |event|
        path = FSSM::Pathname.for(event.absolute_name)
        path = path.dirname unless event.name == "" # Event on root directory
        handler.refresh(path)
      end

      handler.refresh(nil, true) if preload
    end

    def run
      begin
        @notifier.run
      rescue Interrupt
      end
    end

  end
end
