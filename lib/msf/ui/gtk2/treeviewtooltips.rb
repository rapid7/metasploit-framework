module Msf
  module Ui
    module Gtk2

      ##
      # This class perform some tooltips for TreeView widget
      # This class is a port of Daniel J. Popowich coded in Python to ruby-gtk2 style
      ##
      class TreeViewTooltips < Gtk::Window

        def initialize
          super(Gtk::Window::POPUP)
          self.set_resizable(false)
          self.set_border_width(5)
          self.set_app_paintable(true)

          # create the label
          @label = Gtk::Label.new
          @label.set_wrap(true)
          @label.set_alignment(0.5, 0.5)
          @label.set_use_markup(true)
          @label.show()
          self.add(@label)

          # by default, the tooltip is enabled
          @enabled = true
          # saves the current cell
          @save = nil
          # the timer id for the next tooltip to be shown
          @next = nil
          # flag on whether the tooltip window is shown
          @shown = false
        end

        #
        # Enable the tooltip
        #
        def enable
          @enable = true
        end

        #
        # Disable the tooltip
        #
        def disable
          @enable = false
        end


        #
        # Handler to be connected on to the Gtk::Treeview
        #
        def add_view(view)

          # Enter
          view.signal_connect('motion-notify-event') do |view, event|
            motion_handler(view, event)
          end

          # Leave
          view.signal_connect('leave-notify-event') do |view, event|
            leave_handler(view, event)
          end
        end


        #
        # Given the x,y coordinates of the pointer and the width and
        # height (w,h) demensions of the tooltip window, return the x, y
        # coordinates of the tooltip window.
        #
        # The default location is to center the window on the pointer
        # and 20 pixels below it.
        #
        def location(x, y, w, h)
          return x - w/2, y + 20
        end


        #########
        private #
        #########

        #
        # show the tooltip popup with the text/markup given by
        # tooltip.
        #
        # tooltip: the text/markup for the tooltip.
        # x, y:  the coord. (root window based) of the pointer.
        #
        def show(tooltip, x, y)
          # set label
          @label.set_label(tooltip)

          # resize window
          w, h = self.size_request()

          # Display the window with a 1-pixel black border
          self.style.paint_flat_box(	self.window, 		# window: a Gdk::Window
          Gtk::STATE_NORMAL,	# state_type: a state type (GtkStateType)
          Gtk::SHADOW_OUT, 	# shadow_type: a shadow type (GtkShadowType)
          nil, 			# area: a Gdk::Rectangle to which the output is clipped
          self, 			# widget: a Gtk::Widget
          'tooltip', 		# detail: a String or nil
          0, 			# x:
          0, 			# y:
          w, 			# width:
          h			# height:
          )

          # move the window
          self.move(*location(x,y,w,h))

          # show it
          self.show_all
          @shown = true
        end

        #
        # hide the tooltip
        #
        def hide_me
          queue_next()
          self.hide()
          @shown = false
        end

        #
        # When the pointer leaves the view, hide the tooltip
        #
        def leave_handler(view, event)
          hide_me()
        end

        #
        # As the pointer moves across the view, show a tooltip.
        #
        def motion_handler(view, event)

          path = view.get_path_at_pos(event.x, event.y)

          if (@enabled and path)
            path, col, x, y = path
            tooltip = get_tooltip(view, col, path)
            if tooltip
              tooltip = tooltip.strip
              queue_next( [path, col], tooltip, event.x_root, event.y_root)
              return
            end
          end

          hide_me()
        end

        #
        # queue next request to show a tooltip
        #
        def queue_next(*args)

          # if args is non-empty it means a request was made to show a
          # tooltip.  if empty, no request is being made, but any
          # pending requests should be cancelled anyway.

          cell = nil

          # if called with args, break them out
          if args
            cell, tooltip, x, y = args
          end

          # if it's the same cell as previously shown, just return
          if (@save == cell)
            return
          end

          # if we have something queued up, cancel it
          if @next:
            Gtk.timeout_remove(@next)
            @next = nil
          end

          # if there was a request...
          if cell
            # if the tooltip is already shown, show the new one
            # immediately
            if @shown
              show(tooltip, x, y)
              # else queue it up in 1/2 second
            else
              @next = Gtk.timeout_add(500) { show(tooltip, x, y) }
            end
          end

          # save this cell
          @save = cell
        end
      end

    end
  end
end