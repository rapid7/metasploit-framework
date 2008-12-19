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
        # Opcodes statistics
        #
        class Stats < Msf::Ui::Gtk2::SkeletonOpcode

          def initialize
            comment = "Current database statistics :"

            # Call the parent
            super("Statistics", comment)

            self.set_default_size(500, 230)

            begin
              t_run = Thread.new do
                stats = $client.statistics

                textview = Gtk::TextView.new
                textbuffer = Gtk::TextBuffer.new
                stuff.pack_start(textview, true, true, 0)

                textbuffer.set_text(
                "\n" +
                "Last Updated             : #{stats.last_update}\n" +
                "Number of Opcodes        : #{stats.opcodes}\n" +
                "Number of Opcode Types   : #{stats.opcode_types}\n" +
                "Number of Platforms      : #{stats.platforms}\n" +
                "Number of Architectures  : #{stats.architectures}\n" +
                "Number of Modules        : #{stats.modules}\n" +
                "Number of Module Segments: #{stats.module_segments}\n" +
                "Number of Module Imports : #{stats.module_imports}\n" +
                "Number of Module Exports : #{stats.module_exports}\n\n")


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