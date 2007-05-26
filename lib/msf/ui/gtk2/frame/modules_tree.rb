module Msf
  module Ui
    module Gtk2

      ##
      # This class describe the modules treeview
      ##
      class MyModuleTree < MyGlade

        @@completion = []

        PIX, CATEGORY, MODULE, ADV, APP = *(0..5).to_a

        include Msf::Ui::Gtk2::MyControls

        def initialize(treeview, viewmodule)
          super('menu_module')

          @treeview1 = treeview
          @treeview1.enable_search = true

          @model = Gtk::TreeStore.new(	Gdk::Pixbuf,	# pixbuf
          String,		# Module name
          Object,		# Exploit?
          TrueClass,	# ADV?
          String		# Appartenance
          )
          # Register the model for later use
          $gtk2driver.module_model = @model

          # Init buffer module with tags
          buff = Gtk::TextBuffer.new
          viewmodule.set_buffer(buff)
          viewmodule.set_editable(false)
          viewmodule.set_cursor_visible(false)
          @buffer = MyModuleView.new(buff)

          # Renderer Module
          renderer_pix = Gtk::CellRendererPixbuf.new
          renderer_module = Gtk::CellRendererText.new

          column_module = Gtk::TreeViewColumn.new
          column_module.pack_start(renderer_pix, false)
          column_module.set_cell_data_func(renderer_pix) do |column, cell, model, iter|
            cell.pixbuf = iter[PIX]
          end
          column_module.pack_start(renderer_module, true)
          column_module.set_cell_data_func(renderer_module) do |column, cell, model, iter|
            cell.text = iter[CATEGORY]
          end

          #set model to treeview
          @treeview1.set_size_request(380, -1)
          @treeview1.set_model(@model)

          @treeview1.rules_hint = true

          @selection = @treeview1.selection
          @treeview1.selection.mode = Gtk::SELECTION_BROWSE

          @treeview1.append_column(column_module)

          # Signals
          @treeview1.signal_connect('cursor-changed') do |widget, event|
            widget.selection.selected_each do |model, path, iter|
              active(iter)
            end
          end

          @treeview1.signal_connect('button_press_event') do |treeview, event|
            if event.kind_of? Gdk::EventButton

              # Right click
              if (event.button == 3)
                path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
                begin
                  iter = @treeview1.model.get_iter(path)
                  if (iter.get_value(ADV) == false)
                    treeview.selection.select_path(path)
                    active(iter)
                    @menu_module.popup(nil, nil, event.button, event.time)
                  end
                rescue
                  nil
                end

                # Double click
              elsif (event.event_type == Gdk::Event::BUTTON2_PRESS)
                path, column, x, y = treeview.get_path_at_pos(event.x, event.y)
                begin
                  iter = @treeview1.model.get_iter(path)
                  if (iter.get_value(ADV) == false)
                    if (iter.get_value(APP) == "Standard")
                      treeview.selection.select_path(path)
                      active(iter)
                      MsfAssistant::Exploit.new(iter.get_value(MODULE))
                    elsif (iter.get_value(APP) == "Payloads")
                      treeview.selection.select_path(path)
                      active(iter)
                      MsfDialog::Error.new($gtk2driver.main, "Not available")
                    else
                      treeview.selection.select_path(path)
                      active(iter)
                      MsfDialog::Error.new($gtk2driver.main, "Not available")
                    end
                  end
                rescue
                  nil
                end
              end
            end
          end

          @one_shot.signal_connect('activate') do |item|
            if active_module = @selection.selected
              type = active_module.get_value(APP)
              if (type == "Standard")
                MsfAssistant::Exploit.new(active_module.get_value(MODULE))
              elsif (type ==  "Payloads")
                MsfDialog::Error.new($gtk2driver.main, "Not available")
              else
                MsfDialog::Error.new($gtk2driver.main, "Not available")
              end
            end
          end

          # Add modules in the Gtk::TreeView
          add_modules()

          # Configure the module completion handles for easy reference
          $gtk2driver.module_completion = @@completion

        end # def initialize

        #
        # Add Exploits module in the treeview
        #
        def add_modules(filter=/.*/)

          # Add Parent "Standard (nbr exploits)"
          iter = @model.append(nil)
          iter.set_value(PIX, driver.get_icon("bug.png"))
          iter.set_value(CATEGORY, "Exploits (#{framework.stats.num_exploits.to_s})")
          iter.set_value(MODULE, nil)
          iter.set_value(ADV, true)

          # Add Exploits childs
          framework.exploits.each_module do |mod, obj|
            next if not mod.match(filter)
            t_module = obj.new.name
            child_iter = @model.append(iter)
            child_iter.set_value(CATEGORY, t_module)
            child_iter.set_value(MODULE, obj.new)
            child_iter.set_value(ADV, false)
            child_iter.set_value(APP, "Standard")
            @@completion.push(t_module)
          end

          # Add Parent "Auxiliary (nbr auxiliary)"
          iter = @model.append(nil)
          iter.set_value(PIX, driver.get_icon("zoom.png"))
          iter.set_value(CATEGORY, "Auxiliary (#{framework.stats.num_auxiliary.to_s})")
          iter.set_value(MODULE, nil)
          iter.set_value(ADV, true)

          # Add Auxiliary childs
          framework.auxiliary.each_module do |mod, obj|
            next if not mod.match(filter)
            t_module = obj.new.name
            child_iter = @model.append(iter)
            child_iter.set_value(CATEGORY, t_module)
            child_iter.set_value(MODULE, obj.new)
            child_iter.set_value(ADV, false)
            child_iter.set_value(APP, "Auxiliary")
            @@completion.push(t_module)
          end

          # Add Parent "Payloads (nbr payloads)"
          iter = @model.append(nil)
          iter.set_value(PIX, driver.get_icon("bomb.png"))
          iter.set_value(CATEGORY, "Payloads (#{framework.stats.num_payloads.to_s})")
          iter.set_value(MODULE, nil)
          iter.set_value(ADV, true)

          # Add Payloads childs
          framework.payloads.each_module do |mod, obj|
            next if not mod.match(filter)
            t_module = obj.new.name
            child_iter = @model.append(iter)
            child_iter.set_value(CATEGORY, t_module)
            child_iter.set_value(MODULE, obj.new)
            child_iter.set_value(ADV, false)
            child_iter.set_value(APP, "Payloads")
            @@completion.push(t_module)
          end

          # Add Parent "Nops (nbr nops)"
          iter = @model.append(nil)
          iter.set_value(PIX, driver.get_icon("encoders.png"))
          iter.set_value(CATEGORY, "NOPs (#{framework.stats.num_nops.to_s})")
          iter.set_value(MODULE, nil)
          iter.set_value(ADV, true)

          # Add nops childs
          framework.nops.each_module do |mod, obj|
            next if not mod.match(filter)
            t_module = obj.new.name
            child_iter = @model.append(iter)
            child_iter.set_value(CATEGORY, t_module)
            child_iter.set_value(MODULE, obj.new)
            child_iter.set_value(ADV, false)
            child_iter.set_value(APP, "NOPs")
            @@completion.push(t_module)
          end

          # Add Parent "Encoders (nbr encoders)"
          iter = @model.append(nil)
          iter.set_value(PIX, driver.get_icon("encoders.png"))
          iter.set_value(CATEGORY, "Encoders (#{framework.stats.num_encoders.to_s})")
          iter.set_value(MODULE, nil)
          iter.set_value(ADV, true)

          # Add Encoders childs
          framework.encoders.each_module do |mod, obj|
            next if not mod.match(filter)
            t_module = obj.new.name
            child_iter = @model.append(iter)
            child_iter.set_value(CATEGORY, t_module)
            child_iter.set_value(MODULE, obj.new)
            child_iter.set_value(ADV, false)
            iter.set_value(APP, "Encoders")
            @@completion.push(t_module)
          end
        end # def add_modules

        #
        # Display the module information
        #
        def active(iter)
          if not iter[MODULE].nil?
            @buffer.insert_module(iter.get_value(MODULE))
          end
        end

        #
        # Refresh the module treeview with all msf modules
        #
        def refresh
          @model.clear()
          add_modules()
        end

        #
        # remove all iters in array_iter
        #
        def remove(iter_array)

          # first loop to remove unmatched iter
          iter_array.each do |iter|
            if (iter[ADV] == false)
              @model.remove(iter)
            end
          end

          # second loop to update parent iter with child iter
          no_child = []
          @model.each do |model, path, iter|
            if (iter[ADV] == true)
              no_child.push(iter) if not iter.has_child?
              iter[CATEGORY] = iter[CATEGORY].sub(/[0-9]+/, iter.n_children.to_s)
            end
          end

          # remove iter
          no_child.each do |iter|
            @model.remove(iter)
          end
        end

        #
        # expand the treeview
        #
        def expand
          @treeview1.expand_all
        end

      end

    end
  end
end
