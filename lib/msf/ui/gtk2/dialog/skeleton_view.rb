module Msf
  module Ui
    module Gtk2

      class SkeletonView < Gtk::Dialog
        def initialize(title, buffer)
          super(title, $gtk2driver.main, Gtk::Dialog::Flags::MODAL,
          [ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ])

          self.border_width = 10
          self.vbox.spacing = 10
          self.set_default_size(400, 350)

          view = Gtk::TextView.new(buffer)
          scrolled_window = Gtk::ScrolledWindow.new
          scrolled_window.add(view)
          self.vbox.pack_start(scrolled_window, true, true, 5)
          scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
        end
      end
      
    end
  end
end