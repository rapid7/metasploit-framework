module Msf
  module Ui
    module Gtk2

      #
      # Implement a basic window
      #
      class SkeletonBasic < Gtk::Window
        def initialize(title = nil)
          super(Gtk::Window::TOPLEVEL)
          set_title("#{title}")

          signal_connect("key_press_event") do |widget, event|
            if event.state.control_mask? and event.keyval == Gdk::Keyval::GDK_q
              destroy
              true
            else
              false
            end
          end

          signal_connect("delete_event") do |widget, event|
            destroy
            true
          end
        end
      end

    end
  end
end