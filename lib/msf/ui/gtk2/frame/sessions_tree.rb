module Msf
  module Ui
    module Gtk2

      ###
      #
      # This class perform the sessions display
      #
      ###
      class MySessionTree
        ID_SESSION, PEER, TYPE, O_SESSION, O_BUFFER = *(0..5).to_a

        include Msf::Ui::Gtk2::MyControls

        def initialize(treeview)
          @treeview = treeview
          @model = Gtk::ListStore.new(
          String,		# Session ID
          String,		# IP Address
          String,		# Session Type
          Object,		# Session Object
          Object		# Gtk::TextBuffer
          )

          # Renderer
          renderer_id      = Gtk::CellRendererText.new
          renderer_peer    = Gtk::CellRendererText.new
          renderer_type = Gtk::CellRendererText.new

          # ID Session Gtk::TreeViewColumn
          column_id = Gtk::TreeViewColumn.new
          column_id.sizing = Gtk::TreeViewColumn::FIXED
          column_id.fixed_width = 20
          column_id.set_title("ID")
          column_id.pack_start(renderer_id, true)
          column_id.set_cell_data_func(renderer_id) do |column, cell, model, iter|
            cell.text = iter[ID_SESSION]
          end
          column_id.sort_column_id = ID_SESSION

          # Target Gtk::TreeViewColumn
          column_peer = Gtk::TreeViewColumn.new
          column_peer.set_title("Target")
          column_peer.pack_start(renderer_peer, true)
          column_peer.set_cell_data_func(renderer_peer) do |column, cell, model, iter|
            cell.text = iter[PEER]
          end

          # Session type Gtk::TreeViewColumn
          column_type = Gtk::TreeViewColumn.new
          column_type.set_title("Type")
          column_type.pack_start(renderer_type, true)
          column_type.set_cell_data_func(renderer_type) do |column, cell, model, iter|
            cell.text = iter[TYPE]
          end

          # Init tips on the treeview for session
          tips = SessionTips.new(column_type)
          tips.add_view(@treeview)

          #set model to treeview
          @treeview.set_model(@model)

          @selection = @treeview.selection
          @treeview.selection.mode = Gtk::SELECTION_BROWSE
          @treeview.rules_hint = true

          # Add Gtk::TreeViewColumn
          @treeview.append_column(column_id)
          @treeview.append_column(column_peer)
          @treeview.append_column(column_type)

          # TreeView signals
          @treeview.signal_connect('button_press_event') do |treeview, event|
            if event.kind_of? Gdk::EventButton
              if (event.button == 3)
                path, column, x, y = treeview.get_path_at_pos(event.x, event.y)

                begin
                  iter = @treeview.model.get_iter(path)
                  treeview.selection.select_path(path)
                  session = iter[O_SESSION]
                  menu = build_menu(session.type)
                  menu.popup(nil, nil, event.button, event.time)
                rescue
                  nil
                end
              elsif (event.event_type == Gdk::Event::BUTTON2_PRESS)
                path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
                begin
                  iter = @treeview.model.get_iter(path)
                  treeview.selection.select_path(path)
                  open_session(iter)
                rescue
                  nil
                end
              end
            end
          end
        end # def initialize

        #
        # Add an iter to the session treeview
        #
        def add_session(session)
          iter = @model.append
          iter[ID_SESSION] = session.sid.to_s
          iter[PEER] = session.tunnel_peer
          iter[TYPE] = session.type ? session.type : nil
          #iter[PAYLOAD] = session.via_payload ? session.via_payload : nil
          iter[O_SESSION] = session
          iter[O_BUFFER] = nil
        end

        #
        # Open the session with the selected iter
        #
        def open_session(iter)
          Msf::Ui::Gtk2::Console::Shell.new(iter)
        end

        #
        # Kill the session associated with this item
        # TODO: Bug on the sesson kill
        #
        def remove_session_iter(iter)
          # Just kill the session, let the event handler remove it
          iter[O_SESSION].kill
        end

        #
        # Remove the item from the model
        # This is called by the framework on_session_close()
        #
        def remove_session(session)
          found = nil
          @model.each do |model,path,iter|
            if (iter[ID_SESSION] == session.sid.to_s)
              found = iter
              break
            end
          end

          @model.remove(found) if found
        end

        #
        # Build the meterpreter menu and bind signal connect
        #
        def build_menu(type)
          # Session Gtk::Menu
          menu_session = Gtk::Menu.new

          session_item_shell = Gtk::ImageMenuItem.new("Interact Session")
          session_image_shell = Gtk::Image.new
          session_image_shell.set(Gtk::Stock::CONNECT, Gtk::IconSize::MENU)
          session_item_shell.set_image(session_image_shell)
          menu_session.append(session_item_shell)

          if (type == "meterpreter")
            meterpreter_separator = Gtk::SeparatorMenuItem.new
            menu_session.append(meterpreter_separator)

            # Meterpreter shell
            meterpreter_item_shell = Gtk::ImageMenuItem.new("Meterpreter Shell")
            meterpreter_image_shell = Gtk::Image.new
            meterpreter_image_shell.set(Gtk::Stock::EXECUTE, Gtk::IconSize::MENU)
            meterpreter_item_shell.set_image(meterpreter_image_shell)
            # TODO
            # menu_session.append(meterpreter_item_shell)

            # sdapi/process
            meterpreter_proc_item_shell = Gtk::ImageMenuItem.new("Process")
            meterpreter_proc_image_shell = Gtk::Image.new
            meterpreter_proc_image_shell.set(Gtk::Stock::INDEX, Gtk::IconSize::MENU)
            meterpreter_proc_item_shell.set_image(meterpreter_proc_image_shell)
            menu_session.append(meterpreter_proc_item_shell)

            # sdapi/fs
            meterpreter_fs_item_shell = Gtk::ImageMenuItem.new("Browse")
            meterpreter_fs_image_shell = Gtk::Image.new
            meterpreter_fs_image_shell.set(Gtk::Stock::OPEN, Gtk::IconSize::MENU)
            meterpreter_fs_item_shell.set_image(meterpreter_fs_image_shell)
            menu_session.append(meterpreter_fs_item_shell)

            # Meterpreter shell signal
            meterpreter_item_shell.signal_connect('activate') do |item|
              if current = @selection.selected
                Msf::Ui::Gtk2::Console::Meterpreter.new(current)
              end
            end

            # Process signal
            meterpreter_proc_item_shell.signal_connect('activate') do |item|
              if current = @selection.selected
                Msf::Ui::Gtk2::Stdapi::Sys::Ps.new(current[O_SESSION])
              end
            end

            # Fs signal
            meterpreter_fs_item_shell.signal_connect('activate') do |item|
              if current = @selection.selected
                Msf::Ui::Gtk2::Stdapi::Fs.new(current[O_SESSION])
              end
            end
          end

          basic_separator = Gtk::SeparatorMenuItem.new
          menu_session.append(basic_separator)

          close_session_item_shell = Gtk::ImageMenuItem.new("Close Session")
          close_session_image_shell = Gtk::Image.new
          close_session_image_shell.set(Gtk::Stock::CLOSE, Gtk::IconSize::MENU)
          close_session_item_shell.set_image(close_session_image_shell)
          menu_session.append(close_session_item_shell)

          session_item_shell.signal_connect('activate') do |item|
            if current = @selection.selected
              open_session(current)
            end
          end

          close_session_item_shell.signal_connect('activate') do |item|
            if session_iter = @selection.selected
              remove_session_iter(session_iter)
            end
          end

          return menu_session.show_all
        end

      end # class MySessionTree

    end
  end
end