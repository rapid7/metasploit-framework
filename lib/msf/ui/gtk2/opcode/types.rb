module Msf
  module Ui
    module Gtk2

      #
      # Gtk2 Interface for Metasploit Opcodes database
      #
      class MsfOpcode

        # Create the opcode client instance
        $client = Rex::Exploitation::OpcodeDb::Client.new

        #
        # Opcodes types
        #
        class Types < Msf::Ui::Gtk2::SkeletonOpcode
          def initialize
            comment = "Lists of the various specific opcode types supported by the database :"

            # call the parent
            super("Types", comment)

            begin
              t_run = Thread.new do
                textview = Gtk::TextView.new
                textbuffer = Gtk::TextBuffer.new

                scrolled_window = Gtk::ScrolledWindow.new
                scrolled_window.add(textview)
                stuff.pack_start(scrolled_window, true, true, 5)
                scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)

                tps = "\n"
                $client.types.each do |g|
                  tps << " - " + g.name + "\n"
                end

                textbuffer.set_text( tps )

                textview.set_buffer(textbuffer)
                textview.set_editable(false)
                textview.set_cursor_visible(false)

                show_all
              end
              run
              destroy
              t_run.kill
            rescue ::Exception => e
              MsfDialog::Error.new(self, e)
            end

          end

        end

      end

    end
  end
end