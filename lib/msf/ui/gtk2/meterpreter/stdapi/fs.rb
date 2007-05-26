module Msf
  module Ui
    module Gtk2

      class Stdapi

        ###
        #
        # The file system portion of the standard API extension.
        #
        ###
        class Fs <  Msf::Ui::Gtk2::SkeletonBasic
          COL_PATH, COL_DISPLAY_NAME, COL_IS_DIR, COL_PIXBUF = (0..4).to_a

          include Msf::Ui::Gtk2::MyControls

          def initialize(client)

            # The session
            @client = client

            # call the parent
            super("File Browser on #{@client.tunnel_peer}")

            # Define the models (navigation, view)
            # TODO: model for navigation
            @model_view = Gtk::ListStore.new(String, String, TrueClass, Gdk::Pixbuf)
            @model_local = Gtk::TreeStore.new(String, String, TrueClass, Gdk::Pixbuf)

            # Define thes parents
            @parent = "/"
            @parent_local = "/"

            # Define the icons for folders and files
            @file_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_file.png"))
            @folder_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_folder.png"))
            @local_folder_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_local_folder.png"))

            @model_view.set_default_sort_func do |a, b|
              if !a[COL_IS_DIR] and b[COL_IS_DIR]
                1
              elsif a[COL_IS_DIR] and !b[COL_IS_DIR]
                -1
              else
                a[COL_DISPLAY_NAME] <=> b[COL_DISPLAY_NAME]
              end
            end
            @model_view.set_sort_column_id(Gtk::TreeSortable::DEFAULT_SORT_COLUMN_ID, Gtk::SORT_ASCENDING)

            # Define the size and border
            set_default_size(800, 600)
            set_border_width(10)

            # Main hbox
            hbox = Gtk::HBox.new(false, 0)
            add(hbox)

            # Left and right vbox
            vbox_left = Gtk::VBox.new(false, 0)
            vbox_right = Gtk::VBox.new(false, 0)
            hbox.pack_start(vbox_left, false, false, 0)
            hbox.pack_start(vbox_right, true, true, 0)

            # Local
            @treeview_local = Gtk::TreeView.new(@model_local)
            vbox_left.pack_start(@treeview_local, true, true, 0)
            renderer_pix = Gtk::CellRendererPixbuf.new
            renderer_name = Gtk::CellRendererText.new

            column_name = Gtk::TreeViewColumn.new
            column_name.pack_start(renderer_pix, false)
            column_name.set_cell_data_func(renderer_pix) do |column, cell, model, iter|
              cell.pixbuf = iter[COL_PIXBUF]
            end
            column_name.pack_start(renderer_name, true)
            column_name.set_cell_data_func(renderer_name) do |column, cell, model, iter|
              cell.text = iter[COL_DISPLAY_NAME]
            end
            @treeview_local.append_column(column_name)

            # Remote

            # Label, Entry and Signal for the path selection
            hbox_path = Gtk::HBox.new(false, 0)
            vbox_right.pack_start(hbox_path, false, true, 0)
            label_path = Gtk::Label.new("Remote Path :")
            hbox_path.pack_start(label_path, false, false, 0)
            @entry_path = Gtk::Entry.new
            @entry_path.set_text(@client.fs.dir.getwd)
            hbox_path.pack_start(@entry_path, true, true, 0)
            @entry_path.signal_connect('activate') do
              cmd_ls(@entry_path.text)
            end

            # Add the view in the scrolled window
            sw = Gtk::ScrolledWindow.new
            sw.shadow_type = Gtk::SHADOW_ETCHED_IN
            sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox_right.pack_start(sw, true, true, 0)

            iconview = Gtk::IconView.new(@model_view)
            iconview.selection_mode = Gtk::SELECTION_MULTIPLE
            iconview.text_column = COL_DISPLAY_NAME
            iconview.pixbuf_column = COL_PIXBUF
            iconview.signal_connect("item_activated") do |iview, path|
              iter = @model_view.get_iter(path)
              if ( iter[COL_DISPLAY_NAME] and iter[COL_IS_DIR] )
                cmd_ls(@parent + "\\" + iter[COL_DISPLAY_NAME])
              end
            end

            # Populate the view
            local_ls
            cmd_ls

            sw.add(iconview)
            iconview.grab_focus

            show_all
          end

          #
          # Lists file on the remote machine
          #
          def cmd_ls(*args)
            # Try to list the remote path
            begin
              # Just ignore the invalid UTF8
              # Don't know why GLib.filename_to_utf8() don't work ;-(
              ic = Iconv.new('UTF-8//IGNORE', 'UTF-8')

              @model_view.clear
              path = args[0] || @client.fs.dir.getwd
              @parent = path
              @entry_path.set_text(@parent)

              # Enumerate each item...
              @client.fs.dir.entries_with_info(path).sort { |a,b| a['FileName'] <=> b['FileName'] }.each do |p|
                if p['StatBuf'].ftype[0,3] == "dir"
                  is_dir = true
                elsif p['StatBuf'].ftype[0,3] == "fil"
                  is_dir = false
                end
                iter = @model_view.append
                iter[COL_DISPLAY_NAME] = ic.iconv(p['FileName'] + ' ')[0..-2] || 'unknown'
                iter[COL_PATH] = path
                iter[COL_IS_DIR] = is_dir
                iter[COL_PIXBUF] = is_dir ? @folder_pixbuf : @file_pixbuf
              end
              # If not possible return a *warning***
            rescue
              MsfDialog::Warning.new(self, "No entries exist in #{path}")
              cmd_ls
            end
          end # cmd_ls

          def local_ls(*args)
            Dir.glob(File.join(@parent_local, "*")).each do |path|
              if FileTest.directory?(path)
                iter = @model_local.append(nil)
                iter[COL_DISPLAY_NAME] = GLib.filename_to_utf8(File.basename(path))
                iter[COL_PATH] = path
                iter[COL_IS_DIR] = true
                iter[COL_PIXBUF] = @local_folder_pixbuf
              end
            end
          end

        end # Fs

      end

    end
  end
end
