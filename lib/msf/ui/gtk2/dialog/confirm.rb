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
        class Confirm < Msf::Ui::Gtk2::SkeletonAlert
          def initialize(parent, title, message=nil)
            super(parent, title, Gtk::Stock::DIALOG_WARNING,
				[
					[Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL],
					[Gtk::Stock::OK, Gtk::Dialog::RESPONSE_OK]
				],
            	message
			)
            self.default_response = Gtk::Dialog::RESPONSE_CANCEL
			
			signal_connect("response") do |dialog,res_id|
				if(res_id == Gtk::Dialog::RESPONSE_OK)
					yield()
				end
			end
			
            show_all and run
            destroy
          end
        end

      end

    end
  end
end