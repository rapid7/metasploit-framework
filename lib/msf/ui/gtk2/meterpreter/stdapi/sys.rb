module Msf
  module Ui
    module Gtk2

      class Stdapi

        class Sys

          class Ps <  Msf::Ui::Gtk2::SkeletonTree
            PID, NAME, PATH = *(0..3).to_a

            #
            # Lists running processes.
            #
            def initialize(client)
              @model = Gtk::ListStore.new(String, String, String)
              super(client.via_session, @model)

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

              @selection = self.treeview.selection
              self.treeview.selection.mode = Gtk::SELECTION_BROWSE
              self.treeview.rules_hint = true

              populate()
              
              self.default_response = Gtk::Dialog::RESPONSE_NONE
              show_all and run
              destroy
            end

            def populate
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

          end # Ps

        end

      end

    end
  end
end
