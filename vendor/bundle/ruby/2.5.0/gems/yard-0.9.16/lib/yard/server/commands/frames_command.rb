# frozen_string_literal: true
module YARD
  module Server
    module Commands
      # Displays an object wrapped in frames
      class FramesCommand < DisplayObjectCommand
        def run
          options.update(:frames => true, :type => :fulldoc)
          tpl = fulldoc_template
          tpl.generate_frameset
          cache(tpl.contents)
        end
      end
    end
  end
end
