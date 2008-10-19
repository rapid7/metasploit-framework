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
        # Opcodes Platforms
        #
        class Platforms < Msf::Ui::Gtk2::SkeletonOpcode
          def initialize
            comment = "Supported operating system versions broken down by major version and service pack :"

            # call the parent
            super("Platforms", comment)

            begin
              t_run = Thread.new do
                textview = Gtk::TextView.new
                textbuffer = Gtk::TextBuffer.new

                scrolled_window = Gtk::ScrolledWindow.new
                scrolled_window.add(textview)
                stuff.pack_start(scrolled_window, true, true, 5)
                scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)

                ps = "\n"
                $client.platforms.each do |p|
                  ps << " - " + p.desc + "\n"
                end

                textbuffer.set_text( ps )

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