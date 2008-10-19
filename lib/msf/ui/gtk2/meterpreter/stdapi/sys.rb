module Msf
  module Ui
    module Gtk2

      class Stdapi

        ###
        #
        # The system level portion of the standard API extension.
        #
        ###
        class Sys

          class Ps <  Msf::Ui::Gtk2::SkeletonTree
            PID, NAME, PATH = *(0..3).to_a

            #
            # Lists running processes.
            #
            def initialize(client)
              @model = Gtk::ListStore.new(String, String, String)
              super(client.tunnel_peer, @model)

              @client = client

              # Renderer
              renderer_pid  = Gtk::CellRendererText.new
              renderer_name = Gtk::CellRendererText.new
              renderer_path = Gtk::CellRendererText.new

              # PID Gtk::TreeViewColumn
              column_pid = Gtk::TreeViewColumn.new
              column_pid.set_title("PID")
              column_pid.pack_start(renderer_pid, true)
              column_pid.set_cell_data_func(renderer_pid) do |column, cell, model, iter|
                cell.text = iter[PID]
              end
              column_pid.sort_column_id = PID

              # Name Gtk::TreeViewColumn
              column_name = Gtk::TreeViewColumn.new
              column_name.set_title("Name")
              column_name.pack_start(renderer_name, true)
              column_name.set_cell_data_func(renderer_name) do |column, cell, model, iter|
                cell.text = iter[NAME]
              end

              # Path Gtk::TreeViewColumn
              column_path = Gtk::TreeViewColumn.new
              column_path.set_title("Path")
              column_path.pack_start(renderer_path, true)
              column_path.set_cell_data_func(renderer_path) do |column, cell, model, iter|
                cell.text = iter[PATH]
              end

              # Add Gtk::TreeViewColumn
              self.treeview.append_column(column_pid)
              self.treeview.append_column(column_name)
              self.treeview.append_column(column_path)

              # Selection on the treeview stuff
              @selection = self.treeview.selection
              self.treeview.selection.mode = Gtk::SELECTION_BROWSE
              self.treeview.rules_hint = true

              # TreeView signals
              self.treeview.signal_connect('button_press_event') do |treeview, event|
                if event.kind_of? Gdk::EventButton
                  if (event.button == 3)
                    path, column, x, y = treeview.get_path_at_pos(event.x, event.y)

                    begin
                      iter = self.treeview.model.get_iter(path)
                      treeview.selection.select_path(path)
                      menu = build_menu
                      menu.popup(nil, nil, event.button, event.time)
                    rescue
                      nil
                    end

                  end
                end
              end

              # Populate the treeview
              cmd_ps()

              self.default_response = Gtk::Dialog::RESPONSE_NONE
              show_all and run
              destroy
            end

            #
            #
            #
            def build_menu
              # Session Gtk::Menu
              menu_process = Gtk::Menu.new
              
              refresh_item_shell = Gtk::ImageMenuItem.new("Refresh")
              refresh_image_shell = Gtk::Image.new
              refresh_image_shell.set(Gtk::Stock::REFRESH, Gtk::IconSize::MENU)
              refresh_item_shell.set_image(refresh_image_shell)
              menu_process.append(refresh_item_shell)

              migrate_item_shell = Gtk::ImageMenuItem.new("Migrate PID")
              migrate_image_shell = Gtk::Image.new
              migrate_image_shell.set(Gtk::Stock::CONVERT, Gtk::IconSize::MENU)
              migrate_item_shell.set_image(migrate_image_shell)
              menu_process.append(migrate_item_shell)

              kill_item_shell = Gtk::ImageMenuItem.new("Kill")
              kill_image_shell = Gtk::Image.new
              kill_image_shell.set(Gtk::Stock::STOP, Gtk::IconSize::MENU)
              kill_item_shell.set_image(kill_image_shell)
              menu_process.append(kill_item_shell)
              
              # Refresh
              refresh_item_shell.signal_connect('activate') do |item|
                update()
              end

              # Migrate
              migrate_item_shell.signal_connect('activate') do |item|
                if current = @selection.selected
                  cmd_migrate(current.get_value(PID).to_i)
				  update()
                end
              end
              
              # Kill
              kill_item_shell.signal_connect('activate') do |item|
                if current = @selection.selected
                  cmd_kill(current.get_value(PID))
				  update()				  
                end
              end

              return menu_process.show_all
            end

            #
            # Lists running processes.
            #
            def cmd_ps
              processes = @client.sys.process.get_processes
              if (processes.length == 0)
                Msf::Dialog::Error("No running processes were found.")
              else
                processes.each do |ent|
                  iter = @model.append
                  iter[PID]   = ent['pid'].to_s
                  iter[NAME]  = ent['name']
                  iter[PATH]  = ent['path']
                end
              end
            end

            #
            # Update the running list process
            #
            def update
              @model.clear()
              cmd_ps()
            end

            #
            # Kills one or more processes.
            #
            def cmd_kill(*args)
              begin
                @client.sys.process.kill(*(args.map { |x| x.to_i }))
              rescue ::Exception => e
                MsfDialog::Warning.new(self, "Kill Process", e.to_s)
              end
              update()
            end

            #
            # Migrate the server to the supplied process identifier.
            #
            def cmd_migrate(pid)
              old_pid = @client.sys.process.getpid
              @client.core.migrate(pid)

              text = ""
              text << "Migration completed successfully : \n"
              text << "Old PID :#{old_pid}\n"
              text << "New PID :#{@client.sys.process.getpid}"
              MsfDialog::Information.new(self, text)
            end

          end # Ps

        end

      end

    end
  end
end