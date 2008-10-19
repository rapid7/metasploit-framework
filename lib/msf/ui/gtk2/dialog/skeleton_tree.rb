module Msf
  module Ui
    module Gtk2

      class SkeletonTree < Gtk::Dialog
        
        attr_accessor :treeview
        
        def initialize(title, model)
          super(title, $gtk2driver.main, Gtk::Dialog::Flags::MODAL,
          [ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ])

          self.border_width = 10
          self.vbox.spacing = 10
          self.set_default_size(400, 350)

          @treeview = Gtk::TreeView.new(model)
          
          scrolled_window = Gtk::ScrolledWindow.new
          scrolled_window.add(@treeview)
          self.vbox.pack_start(scrolled_window, true, true, 5)
          scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
        end
      end

    end
  end
end