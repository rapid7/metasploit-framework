module Msf
  module Ui
    module Gtk2

      ###
      #
      # Subclass the TreeViewTooltips to add our get_tooltip function
      #
      ###
      class AssistantTips < Msf::Ui::Gtk2::TreeViewTooltips

        def initialize(column)
          super()
          @column = column
        end

        def get_tooltip(view, column, path)
          if (column == @column)
            model = view.model
            iter = model.get_iter(path)
            return iter.get_value(3)
          end
        end
        
      end # AssistantTips
      
    end
  end
end