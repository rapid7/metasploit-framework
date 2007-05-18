module Msf
  module Ui
    module Gtk2

      class MsfDialog
        ##
        # Display an error Gtk style
        # parent: the Gtk parent widget
        # title: the error title
        # message: the error
        ##
        class Information < Msf::Ui::Gtk2::SkeletonAlert
          def initialize(parent, title, message=nil)
            super(parent, title, Gtk::Stock::DIALOG_INFO,
            [[Gtk::Stock::OK, Gtk::Dialog::RESPONSE_OK]],
            message)
            self.default_response = Gtk::Dialog::RESPONSE_OK
            show_all and run
            destroy
          end
        end
      end
    end
  end
end