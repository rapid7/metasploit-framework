module Msf
  module Ui
    module Gtk2

      #
      # Implement a basic window
      #
      class SkeletonBrowser < Gtk::Window

        COL_TYPE, COL_PATH, COL_DISPLAY_NAME, COL_IS_DIR, COL_PIXBUF = (0..5).to_a
        DOWNLOAD_TARGET_TABLE = ["DOWNLOAD", Gtk::Drag::TARGET_SAME_APP, 0]
        UPLOAD_TARGET_TABLE = ["UPLOAD", Gtk::Drag::TARGET_SAME_APP, 0]

        include Msf::Ui::Gtk2::MyControls

        attr_accessor :parent_local, :parent_remote, :remote_path, :local_path, :model_remote, :model_local
        attr_reader :file_pixbuf, :folder_pixbuf

        def initialize(title = nil, local = "", remote = "")
          super(Gtk::Window::TOPLEVEL)
          set_title("#{title}")

          signal_connect("key_press_event") do |widget, event|
            if event.state.control_mask? and event.keyval == Gdk::Keyval::GDK_q
              destroy
              true
            else
              false
            end
          end

          signal_connect("delete_event") do |widget, event|
            destroy
            true
          end

          # Define the size and border
          set_default_size(1000, 600)
          set_border_width(10)

          # Define the models (navigation, view)
          # TODO: model for navigation
          @model_local = Gtk::ListStore.new(String, String, String, TrueClass, Gdk::Pixbuf)
          @model_remote = Gtk::ListStore.new(String, String, String, TrueClass, Gdk::Pixbuf)

          # Define thes parents
          @parent_local = local
          @parent_remote = remote
          @parent_remote_init = remote

          # Define the icons for folders and files
          @file_pixbuf = driver.get_icon("msf_file.xpm")
          @folder_pixbuf = driver.get_icon("msf_folder.xpm")
          @local_folder_pixbuf = driver.get_icon("msf_local_folder.xpm")

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
          vbox_paned = Gtk::HPaned.new
          vbox_paned.set_size_request(900, -1)
          hbox.pack_start(vbox_paned, true, true, 0)
          vbox_paned.pack1(vbox_left, true, false)
          vbox_paned.pack2(vbox_right, true, false)

          #
          # Local
          #
          # Label, Entry and Signal for the path selection
          vbox_left.pack_start( menu_toolbar(), false, false )
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
              local_ls(@parent_local + File::SEPARATOR + iter[COL_DISPLAY_NAME])
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
          vbox_right.pack_start( menu_toolbar("meterpreter"), false, false )
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

          sw_remote.add(@iconview_remote)
          sw_local.add(@iconview_local)
          @iconview_remote.grab_focus

          show_all
        end # initialize

        #
        # Build a toolbar menu
        #
        def menu_toolbar(context="")
          toolbar = Gtk::Toolbar.new

          up_button = Gtk::ToolButton.new(Gtk::Stock::GO_UP)
          up_button.important = true
          up_button.sensitive = true
          toolbar.insert(-1, up_button)
          up_button.signal_connect("clicked") do
            if (context == "meterpreter")
              parent = dirname_up(@parent_remote)
              remote_ls(parent)
            else
              parent = File.dirname(@parent_local)
              local_ls(parent)
            end
            # up_button.sensitive = @parent != "/"
          end
          home_button = Gtk::ToolButton.new(Gtk::Stock::HOME)
          home_button.important = true
          toolbar.insert(-1, home_button)
          home_button.signal_connect("clicked") do
            if (context == "meterpreter")
              parent = @parent_remote_init
              remote_ls(parent)
            else
              parent = GLib.home_dir
              local_ls(parent)
            end
            up_button.sensitive = true
          end
          
          refresh_button = Gtk::ToolButton.new(Gtk::Stock::REFRESH)
          refresh_button.important = true
          toolbar.insert(-1, refresh_button)
          refresh_button.signal_connect("clicked") do
            if (context == "meterpreter")
              remote_ls()
            else
              local_ls()
            end
            up_button.sensitive = true
            
          end

          return toolbar
        end # menu_toolbar

        #
        # Return an array containing all the selected widgets
        #
        def selected_fs(view)
          fs = []
          view.selected_each do |iconview, path|
            iter = view.model.get_iter(path)
            if iter.get_value(COL_TYPE) == "local"
              fs << iter.get_value(COL_PATH) + File::SEPARATOR + iter.get_value(COL_DISPLAY_NAME)
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
        # Return files widgets specified by the given directory on the remote machine
        #
        def remote_ls(*args)
          raise NotImplementedError, "Subclass must implement remote_ls()"
        end # remote_ls

        #
        # Return files widgets specified by the given directory on the local machine
        #
        def local_ls(*args)
          begin
            @model_local.clear
            path = args[0] || @parent_local
            path = dirname(path)
            @local_path.set_text(path)

            Dir.entries(path).each do |file|
              if FileTest.directory?(path + File::SEPARATOR + file)
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
        # Dummy function for download method
        #
        def cmd_download
          raise NotImplementedError, "Subclass must implement cmd_download()"
        end

        #
        # Dummy function for upload method
        #
        def cmd_upload
          raise NotImplementedError, "Subclass must implement cmd_upload()"
        end

        #
        # Parsing for local entry
        #
        def dirname(path)
          sep  = File::SEPARATOR
          path =~ /(.*)#{sep}(.*)#{sep}(.|..)$/

          if ($3 == ".")
            return $1 + sep + $2
          elsif ($3 == "..")
            return $1
          else
            return path
          end
        end # dirname

        #
        # Parsing for remote entry
        #
        def dirname_meter(path)
          path =~ /(.*)\\(.*)\\(.|..)$/

          if ($3 == ".")
            return $1 + "\\" + $2
          elsif ($3 == "..")
            return $1
          else
            return path
          end
        end # dirname_meter

        #
        # Parsing for remote entry (up button)
        #
        def dirname_up(path)
          path =~ /(.*)\\(.*)$/

          return $1 || path
        end

      end

    end
  end
end
