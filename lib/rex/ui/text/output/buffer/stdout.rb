# make sure the classes are defined before opening it to define submodule
require 'rex/ui/text/output'
require 'rex/ui/text/output/buffer'

module Rex
  module Ui
    module Text
      class Output
        class Buffer
          # Adds {#write} method to {Rex::Ui::Text::Output::Buffer} so it can
          # function as a stand-in for `$stdout`
          module Stdout
            # Prints raw message.
            #
            # @param (see Rex::Ui::Text::Output::Buffer#write)
            # @return (see Rex::Ui::Text::Output::Buffer#write)
            def write(msg = '')
              print_raw(msg)
            end
          end
        end
      end
    end
  end
end