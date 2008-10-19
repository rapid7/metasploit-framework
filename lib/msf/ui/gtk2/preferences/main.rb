module Msf
  module Ui
    module Gtk2

      class MsfPreferences

        #
        # This class is dedicated to the options stuff
        #
        class Main < Gtk::Dialog

          include Msf::Ui::Gtk2::MyControls

          def initialize
            # Array for the face buttons
            buttons = [ Gtk::Stock::OK, Gtk::Dialog::RESPONSE_OK ], [ Gtk::Stock::CLOSE, Gtk::Dialog::RESPONSE_NONE ]

            # call the parent
            super("Preferences", $gtk2driver.main, Gtk::Dialog::DESTROY_WITH_PARENT, *buttons)
            self.default_response = Gtk::Dialog::RESPONSE_OK  
            
            # Define the size and border
            set_default_size(400, 400)
            # set_border_width(10)
            
            # Notebook
            @notebook = Gtk::Notebook.new()
            
            # Databases page
            database = MsfPreferences::Databases.new()
            
            # append database page
            @notebook.append_page(database.page, database.label)
            
            # append another pages here ;-)
            # <!here>
            
            @notebook.tab_pos = Gtk::POS_TOP
            vbox.add(@notebook)
            @notebook.border_width = 10

            @notebook.realize
            
            signal_connect('response') do |dialog, response_id|
              if response_id == Gtk::Dialog::RESPONSE_OK
                begin
                  # collect()
                rescue ::Exception => e
                  MsfDialog::Error.new(self, e)
                end
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