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
            @client = client
            super("MsfBrowser on #{@client.tunnel_peer}")
            @model = Gtk::ListStore.new(String, String, TrueClass, Gdk::Pixbuf)
            @parent = "/"

            @file_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_file.png"))
            @folder_pixbuf = Gdk::Pixbuf.new(driver.get_image("msf_folder.png"))

            @model.set_default_sort_func do |a, b|
              if !a[COL_IS_DIR] and b[COL_IS_DIR]
                1
              elsif a[COL_IS_DIR] and !b[COL_IS_DIR]
                -1
              else
                a[COL_DISPLAY_NAME] <=> b[COL_DISPLAY_NAME]
              end
            end
            @model.set_sort_column_id(Gtk::TreeSortable::DEFAULT_SORT_COLUMN_ID, Gtk::SORT_ASCENDING)

            # Populate the ListStore
            cmd_ls

            # Define the size and border
            set_default_size(650, 400)
            set_border_width(10)

            vbox = Gtk::VBox.new(false, 0)
            add(vbox)

            # Add the view in the scrolled window
            sw = Gtk::ScrolledWindow.new
            sw.shadow_type = Gtk::SHADOW_ETCHED_IN
            sw.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
            vbox.pack_start(sw, true, true, 0)

            iconview = Gtk::IconView.new(@model)
            iconview.selection_mode = Gtk::SELECTION_MULTIPLE
            iconview.text_column = COL_DISPLAY_NAME
            iconview.pixbuf_column = COL_PIXBUF
            iconview.signal_connect("item_activated") do |iview, path|
              iter = @model.get_iter(path)
              if iter[COL_DISPLAY_NAME]
                @parent = iter[COL_PATH]
                cmd_ls
              end
            end
            
            sw.add(iconview)
            iconview.grab_focus

            show_all
          end

          def cmd_ls(*args)
            @model.clear
            path = args[0] || @client.fs.dir.getwd

            # Enumerate each item...
            @client.fs.dir.entries_with_info(path).sort { |a,b| a['FileName'] <=> b['FileName'] }.each do |p|
              if p['StatBuf'].ftype[0,3] == "dir"
                is_dir = true
              elsif p['StatBuf'].ftype[0,3] == "fil"
                is_dir = false
              end
              iter = @model.append
              iter[COL_DISPLAY_NAME] = p['FileName'] || 'unknown'
              iter[COL_PATH] = path
              iter[COL_IS_DIR] = is_dir
              iter[COL_PIXBUF] = is_dir ? @folder_pixbuf : @file_pixbuf
            end

          end # cmd_ls

        end # Fs

      end

    end
  end
end
