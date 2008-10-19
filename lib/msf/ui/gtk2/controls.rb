module Msf
  module Ui
    module Gtk2

      module MyControls

        #
        # Included class methods
        #

        # Get the global driver handle
        def driver
          $gtk2driver
        end

        # Return the framework instance from the driver handler
        def framework
          driver.framework
        end

        def log(msg)
          if ($gtk2logger)
            $gtk2logger.append_text(msg + "\n")
          else
            # $stderr.puts Time.now.to_s + " " + msg
          end
        end

        #
        # Controls
        #

        # TODO: Add control here

      end

    end
  end
end