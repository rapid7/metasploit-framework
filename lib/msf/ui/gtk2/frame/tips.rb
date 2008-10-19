module Msf
  module Ui
    module Gtk2

      #
      # Subclass the TreeViewTooltips to add our get_tooltip function
      #
      class SessionTips < Msf::Ui::Gtk2::TreeViewTooltips

        def initialize(column)
          super()
          @column = column
        end

        def get_tooltip(view, column, path)
          if (column == @column)
            model = view.model
            iter = model.get_iter(path)

            @session = iter.get_value(3)

            if (@session.type ==  "meterpreter")
              begin
                tips = meterpreter_tips
              rescue
                nil
              end
            else
              begin
                tips = shell_tips
              rescue
                nil
              end
            end

            return tips
          end

          #
          # Shell session tips
          #
          def shell_tips
            text = ""
            text << "Exploit: #{@session.via_exploit} \n"
            text << "Payload: #{@session.via_payload}"
          end

          #
          # Meterpreter session tips
          #
          def meterpreter_tips
            text = ""
            text << "Exploit: #{@session.via_exploit} \n"
            text << "Payload: #{@session.via_payload} \n"
            text << "PID: #{@session.sys.process.getpid}"
          end

          #
          # VNCInject session tips
          #
          def vncinject_tips
            shell_tips()
          end

        end
      end


    end
  end
end