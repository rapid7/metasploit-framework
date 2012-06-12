# encoding: utf-8

module CarrierWave
  module Uploader
    module Processing
      extend ActiveSupport::Concern

      include CarrierWave::Uploader::Callbacks

      included do
        class_attribute :processors, :instance_writer => false
        self.processors = []

        after :cache, :process!
      end

      module ClassMethods

        ##
        # Adds a processor callback which applies operations as a file is uploaded.
        # The argument may be the name of any method of the uploader, expressed as a symbol,
        # or a list of such methods, or a hash where the key is a method and the value is
        # an array of arguments to call the method with
        #
        # === Parameters
        #
        # args (*Symbol, Hash{Symbol => Array[]})
        #
        # === Examples
        #
        #     class MyUploader < CarrierWave::Uploader::Base
        #
        #       process :sepiatone, :vignette
        #       process :scale => [200, 200]
        #       process :scale => [200, 200], :if => :image?
        #       process :sepiatone, :if => :image?
        #
        #       def sepiatone
        #         ...
        #       end
        #
        #       def vignette
        #         ...
        #       end
        #
        #       def scale(height, width)
        #         ...
        #       end
        #
        #       def image?
        #         ...
        #       end
        #
        #     end
        #
        def process(*args)
          if !args.first.is_a?(Hash) && args.last.is_a?(Hash)
            conditions = args.pop
            args.map!{ |arg| {arg => []}.merge(conditions) }
          end

          args.each do |arg|
            if arg.is_a?(Hash)
              condition = arg.delete(:if)
              arg.each do |method, args|
                self.processors += [[method, args, condition]]
              end
            else
              self.processors += [[arg, [], nil]]
            end
          end
        end

      end # ClassMethods

      ##
      # Apply all process callbacks added through CarrierWave.process
      #
      def process!(new_file=nil)
        if enable_processing
          self.class.processors.each do |method, args, condition|
            if(condition)
              next if !(condition.respond_to?(:call) ? condition.call(self, :args => args, :method => method, :file => new_file) : self.send(condition, new_file))
            end
            self.send(method, *args)
          end
        end
      end

    end # Processing
  end # Uploader
end # CarrierWave
