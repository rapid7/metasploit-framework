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
          COL_TYPE, COL_PATH, COL_DISPLAY_NAME, COL_IS_DIR, COL_PIXBUF = (0..5).to_a
          DOWNLOAD_TARGET_TABLE = ["DOWNLOAD", Gtk::Drag::TARGET_SAME_APP, 0]
          UPLOAD_TARGET_TABLE = ["UPLOAD", Gtk::Drag::TARGET_SAME_APP, 0]

          include Msf::Ui::Gtk2::MyControls

          def initialize(client)

            # The session
            @client = client

            # call the parent
            super("MsfBrowser on #{@client.tunnel_peer}")

            # Define the size and border
            set_default_size(1000, 600)
            set_border_width(10)

            # Define the models (navigation, view)
            # TODO: model for navigation
            @model_local = Gtk::ListStore.new(String, String, String, TrueClass, Gdk::Pixbuf)
            @model_remote = Gtk::ListStore.new(String, String, String, TrueClass, Gdk::Pixbuf)

            # Define thes parents
            @parent_local = File.join(driver.resource_directory, "sessions")
            @parent_remote = "/"

            # Define the icons for folders and files
            @file_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_file.png"))
            @folder_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_folder.png"))
            @local_folder_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_local_folder.png"))

            @model_local.set_default_sort_func do |a, b|
              if !a[COL_IS_DIR] and b[COL_IS_DIR]
                1
              elsif a[COL_IS_DIR] and !b[COL_IS_DIR]
                -1
              else
                a[COL_DISPLAY_NAME] <=> b[COL_DISPLAY_NAME]
              end
            end
            @model_local.set_sort_column_id(Gtk::TreeSortable::DEFAULT_SORT_COLUMN_ID, Gtk::SORT_ASCENDING)

            @model_remote.set_default_sort_func do |a, b|
              if !a[COL_IS_DIR] and b[COL_IS_DIR]
                1
              elsif a[COL_IS_DIR] and !b[COL_IS_DIR]
                -1
              else
                a[COL_DISPLAY_NAME] <=> b[COL_DISPLAY_NAME]
              end
            end
            @model_remote.set_sort_column_id(Gtk::TreeSortable::DEFAULT_SORT_COLUMN_ID, Gtk::SORT_ASCENDING)

            # Main hbox
            hbox = Gtk::HBox.new(false, 0)
            add(hbox)

            # Left and right vbox
            vbox_left = Gtk::VBox.new(false, 0)
            vbox_right = Gtk::VBox.new(false, 0)
            hbox.pack_start(vbox_left, true, true, 0)
            hbox.pack_start(vbox_right, true, true, 0)

            #
            # Local
            #
            # Label, Entry and Signal for the path selection
            hbox_path = Gtk::HBox.new(false, 0)
            vbox_left.pack_start(hbox_path, false, true, 0)
            local_label_path = Gtk::Label.new("Local Path :")
            hbox_path.pack_start(local_label_path, false, false, 0)
            @local_path = Gtk::Entry.new
            @local_path.set_text(@parent_local)
            hbox_path.pack_start(@local_path, true, true, 0)
            @local_path.signal_connect('activate') do
              local_ls(@local_path.text)
            end

            # Add the view in the scrolled window
            sw_local = Gtk::ScrolledWindow.new
            sw_local.shadow_type = Gtk::SHADOW_ETCHED_IN
            sw_local.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox_left.pack_start(sw_local, true, true, 0)

            @iconview_local = Gtk::IconView.new(@model_local)
            @iconview_local.selection_mode = Gtk::SELECTION_MULTIPLE
            @iconview_local.orientation = Gtk::ORIENTATION_VERTICAL
            @iconview_local.text_column = COL_DISPLAY_NAME
            @iconview_local.pixbuf_column = COL_PIXBUF
            @iconview_local.signal_connect("item_activated") do |iview, path|
              iter = @model_local.get_iter(path)
              if ( iter[COL_DISPLAY_NAME] and iter[COL_IS_DIR] )
                local_ls(@parent_local + ::File::SEPARATOR + iter[COL_DISPLAY_NAME])
              end
            end
            # Enable drag'n drop if Gtk+ 2.8.0
            if @iconview_local.respond_to?(:enable_model_drag_source)
              setup_drop(@iconview_local)
              setup_drag_local()
            end

            #
            # Remote iconview
            #
            # Label, Entry and Signal for the path selection
            hbox_path = Gtk::HBox.new(false, 0)
            vbox_right.pack_start(hbox_path, false, true, 0)
            label_path = Gtk::Label.new("Remote Path :")
            hbox_path.pack_start(label_path, false, false, 0)
            @remote_path = Gtk::Entry.new
            @remote_path.set_text(@client.fs.dir.getwd)
            hbox_path.pack_start(@remote_path, true, true, 0)
            @remote_path.signal_connect('activate') do
              remote_ls(@remote_path.text)
            end

            # Add the view in the scrolled window
            sw_remote = Gtk::ScrolledWindow.new
            sw_remote.shadow_type = Gtk::SHADOW_ETCHED_IN
            sw_remote.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox_right.pack_start(sw_remote, true, true, 0)

            @iconview_remote = Gtk::IconView.new(@model_remote)
            @iconview_remote.selection_mode = Gtk::SELECTION_MULTIPLE
            @iconview_remote.text_column = COL_DISPLAY_NAME
            @iconview_remote.pixbuf_column = COL_PIXBUF
            @iconview_remote.signal_connect("item_activated") do |iview, path|
              iter = @model_remote.get_iter(path)
              if ( iter[COL_DISPLAY_NAME] and iter[COL_IS_DIR] )
                remote_ls(@parent_remote + "\\" + iter[COL_DISPLAY_NAME])
              end
            end
            # Enable drag'n drop if Gtk+ 2.8.0
            if @iconview_remote.respond_to?(:enable_model_drag_source)
              setup_drop(@iconview_remote)
              setup_drag_remote()
            end

            # Populate the view
            create_dir_session()
            local_ls
            remote_ls

            sw_remote.add(@iconview_remote)
            sw_local.add(@iconview_local)
            @iconview_remote.grab_focus

            show_all
          end

          #
          # Return files widgets specified by the given directory on the remote machine
          #
          def remote_ls(*args)
            # Try to list the remote path
            begin
              # Just ignore the invalid UTF8
              # Don't know why GLib.filename_to_utf8() don't work ;-(
              ic = Iconv.new('UTF-8//IGNORE', 'UTF-8')

              @model_remote.clear
              path = args[0] || @client.fs.dir.getwd
              @remote_path.set_text(path)

              # Enumerate each item...
              @client.fs.dir.entries_with_info(path).sort { |a,b| a['FileName'] <=> b['FileName'] }.each do |p|
                if p['StatBuf'].ftype[0,3] == "dir"
                  is_dir = true
                elsif p['StatBuf'].ftype[0,3] == "fil"
                  is_dir = false
                end
                iter = @model_remote.append
                iter[COL_DISPLAY_NAME] = ic.iconv(p['FileName'] + ' ')[0..-2] || 'unknown'
                iter[COL_PATH] = path
                iter[COL_IS_DIR] = is_dir
                iter[COL_PIXBUF] = is_dir ? @folder_pixbuf : @file_pixbuf
                iter[COL_TYPE] = "remote"
              end
              @parent_remote = path

              # If not possible return a *warning*
            rescue ::Exception => e
              MsfDialog::Warning.new(self, "Remote browser", e.to_s)
              remote_ls
            end
          end # remote_ls

          #
          # Return files widgets specified by the given directory on the local machine
          #
          def local_ls(*args)
            begin
              @model_local.clear
              path = args[0] || @parent_local
              @local_path.set_text(path)

              Dir.entries(path).each do |file|
                if FileTest.directory?(path + ::File::SEPARATOR + file)
                  is_dir = true
                else
                  is_dir = false
                end
                iter = @model_local.append
                iter[COL_DISPLAY_NAME] = GLib.filename_to_utf8(file)
                iter[COL_PATH] = path
                iter[COL_IS_DIR] = is_dir
                iter[COL_PIXBUF] = is_dir ? @folder_pixbuf : @file_pixbuf
                iter[COL_TYPE] = "local"
              end
              @parent_local = path

              # If not possible return a *warning***
            rescue ::Exception => e
              MsfDialog::Warning.new(self, "Local Browser", e.to_s)
              local_ls
            end
          end #local_ls

          #
          # Create a directory per session
          #
          def create_dir_session
            begin
              Dir.mkdir(File.join(@parent_local, @client.tunnel_peer.to_s.split(":")[0]))
            rescue
              nil
            end
          end

          #
          # Return an array containing all the selected widgets
          #
          def selected_fs(view)
            fs = []
            view.selected_each do |iconview, path|
              iter = view.model.get_iter(path)
              if iter.get_value(COL_TYPE) == "local"
                fs << iter.get_value(COL_PATH) + ::File::SEPARATOR + iter.get_value(COL_DISPLAY_NAME)
              else
                fs << iter.get_value(COL_PATH) + "\\" + iter.get_value(COL_DISPLAY_NAME)
              end
            end
            fs.select { |x| x != nil }
          end

          #
          # Drag stuff for local view
          #
          def setup_drag_local

            Gtk::Drag.source_set(@iconview_local,
            Gdk::Window::BUTTON1_MASK | Gdk::Window::BUTTON2_MASK,
            [UPLOAD_TARGET_TABLE],
            Gdk::DragContext::ACTION_COPY | Gdk::DragContext::ACTION_MOVE)

            @iconview_local.signal_connect("drag_data_get") do |widget, context, selection_data, info, time|
              files = selected_fs(@iconview_local).map do |file| file.to_s end
              unless files.empty?
                selection_data.set(Gdk::Selection::TYPE_STRING, files.join(','))
              end
            end
          end
          
          #
          # Drag stuff for remote view
          #
          def setup_drag_remote

            Gtk::Drag.source_set(@iconview_remote,
            Gdk::Window::BUTTON1_MASK | Gdk::Window::BUTTON2_MASK,
            [DOWNLOAD_TARGET_TABLE],
            Gdk::DragContext::ACTION_COPY | Gdk::DragContext::ACTION_MOVE)

            @iconview_remote.signal_connect("drag_data_get") do |widget, context, selection_data, info, time|
              files = selected_fs(@iconview_remote).map do |file| file.to_s end
              unless files.empty?
                selection_data.set(Gdk::Selection::TYPE_STRING, files.join(','))
              end
            end
          end

          #
          # Drop stuff
          #
          def setup_drop(view)
            Gtk::Drag.dest_set(view,
            Gtk::Drag::DEST_DEFAULT_MOTION | Gtk::Drag::DEST_DEFAULT_HIGHLIGHT,
            [UPLOAD_TARGET_TABLE, DOWNLOAD_TARGET_TABLE],
            Gdk::DragContext::ACTION_COPY | Gdk::DragContext::ACTION_MOVE)

            view.signal_connect("drag-data-received") do |w, dc, x, y, selectiondata, info, time|
              dc.targets.each do |target|
                if selectiondata.type == Gdk::Selection::TYPE_STRING
                  if target.name == "DOWNLOAD"
                    cmd_download(selectiondata.data)
                    local_ls
                  elsif target.name == "UPLOAD"
                    cmd_upload(selectiondata.data)
                    remote_ls
                  end
                end
              end
            end
            view.signal_connect("drag-drop") do |w, dc, x, y, time|
              Gtk::Drag.get_data(w, dc, dc.targets[0], time)
            end
          end

          #
          # Downloads a file or directory from the remote machine to the local
          # machine.
          #
          def cmd_download(*args)

            recursive = true
            src_items = args
            dest = @parent_local

            begin
              # If there is no destination, assume it's the same as the source.
              if (!dest)
                dest = src_items[0]
              end

              # Go through each source item and download them
              src_items.each { |src|
                stat = @client.fs.file.stat(src)

                if (stat.directory?)
                  @client.fs.dir.download(dest, src, recursive) { |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  }
                elsif (stat.file?)
                  @client.fs.file.download(dest, src) { |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  }
                end
              }

            rescue ::Exception => e
              MsfDialog::Warning.new(self, "Operation failed", e.to_s)
            end

            return true
          end #cmd_download

          #
          # Uploads a file or directory to the remote machine from the local
          # machine.
          #
          def cmd_upload(*args)

            recursive = true
            src_items = args
            dest = @parent_remote

            begin
              # If there is no destination, assume it's the same as the source.
              if (!dest)
                dest = src_items[0]
              end

              # Go through each source item and upload them
              src_items.each { |src|
                stat = ::File.stat(src)

                if (stat.directory?)
                  @client.fs.dir.upload(dest, src, recursive) { |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  }
                elsif (stat.file?)
                  @client.fs.file.upload(dest, src) { |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  }
                end
              }
            rescue  ::Exception => e
              MsfDialog::Warning.new(self, "Upload: Operation failed", e.to_s)
            end

            return true
          end # cmd_upload

        end # Fs

      end

    end
  end
end
