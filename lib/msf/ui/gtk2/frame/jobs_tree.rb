module Msf
  module Ui
    module Gtk2

      class MyJobTree < MyGlade
        PIX, JID, NAME = *(0..3).to_a

        include Msf::Ui::Gtk2::MyControls

        #
        # This module help us to modify the Rex::JobContainer class behavior
        #
        module ModifiedJobContainer

          #
          # Adds an already running task as a symbolic job to the container.
          #
          def add_job(name, ctx, run_proc, clean_proc)
            real_name = name
            count     = 0
            jid       = job_id_pool

            self.job_id_pool += 1

            # If we were not supplied with a job name, pick one from the hat
            if (real_name == nil)
              real_name = '#' + jid.to_s
            end

            # Find a unique job name
            while (j = self[real_name])
              real_name  = name + " #{count}"
              count     += 1
            end

            j = Rex::Job.new(self, jid, real_name, ctx, run_proc, clean_proc)

            $gtk2driver.job_tree.add_oneshot(jid, name)
            self[jid.to_s] = j
          end

          #
          # Removes a job that was previously running.  This is typically called when
          # a job completes its task.
          #
          def remove_job(inst)
            self.delete(inst.jid.to_s)
            $gtk2driver.job_tree.remove_job(inst.jid.to_s)
          end

        end # module

        def initialize(treeview)
          framework.jobs.extend(ModifiedJobContainer)

          @treeview2 = treeview

          @model = Gtk::TreeStore.new(
          Gdk::Pixbuf,	# Pix rhost
          String, 	# process JID
          String 	# module name
          )

          # Renderer
          renderer_pix = Gtk::CellRendererPixbuf.new
          renderer_JID = Gtk::CellRendererText.new
          renderer_name = Gtk::CellRendererText.new

          # JID Gtk::TreeViewColumn
          column_JID = Gtk::TreeViewColumn.new
          column_JID.set_title("Job ID")
          column_JID.pack_start(renderer_pix, false)
          column_JID.set_cell_data_func(renderer_pix) do |column, cell, model, iter|
            cell.pixbuf = iter[PIX]
          end
          column_JID.pack_start(renderer_JID, true)
          column_JID.set_cell_data_func(renderer_JID) do |column, cell, model, iter|
            cell.text = iter[JID]
          end
          column_JID.sort_column_id = JID

          # Name Gtk::TreeViewColumn
          column_name = Gtk::TreeViewColumn.new
          column_name.set_title("Module")
          column_name.pack_start(renderer_name, true)
          column_name.set_cell_data_func(renderer_name) do |column, cell, model, iter|
            cell.text = iter[NAME]
          end

          #set model to treeview
          @treeview2.set_model(@model)

          @selection = @treeview2.selection
          @treeview2.selection.mode = Gtk::SELECTION_BROWSE
          @treeview2.rules_hint = true

          # Add Gtk::TreeViewColumn
          @treeview2.append_column(column_JID)
          @treeview2.append_column(column_name)

          # Add AutoPWN - DISABLED FOR NOW
		  # @autopwn_iter = @model.append(nil)
          # @autopwn_iter.set_value(PIX, driver.get_icon("menu_autopwn.xpm"))
          # @autopwn_iter.set_value(JID, "AutoPWN")

          # Add Parent "One shot"
          @oneshot_iter = @model.append(nil)
          @oneshot_iter.set_value(PIX, driver.get_icon("menu_oneshot.xpm"))
          @oneshot_iter.set_value(JID, "Jobs")

          # Job Gtk::Menu
          @menu_job = Gtk::Menu.new
          @menu_refresh = Gtk::Menu.new
          
          # Stop job
          kill_job_item_shell = Gtk::ImageMenuItem.new("Kill Job")
          kill_job_image_shell = Gtk::Image.new
          kill_job_image_shell.set(Gtk::Stock::CLOSE, Gtk::IconSize::MENU)
          kill_job_item_shell.set_image(kill_job_image_shell)
          @menu_job.append(kill_job_item_shell)

          # Refresh
          refresh_job_item_shell = Gtk::ImageMenuItem.new("Refresh")
          refresh_job_image_shell = Gtk::Image.new
          refresh_job_image_shell.set(Gtk::Stock::REFRESH, Gtk::IconSize::MENU)
          refresh_job_item_shell.set_image(refresh_job_image_shell)
          @menu_job.append(refresh_job_item_shell)
          
          refresh_job_item_shell2 = Gtk::ImageMenuItem.new("Refresh")
          refresh_job_image_shell2 = Gtk::Image.new
          refresh_job_image_shell2.set(Gtk::Stock::REFRESH, Gtk::IconSize::MENU)
          refresh_job_item_shell2.set_image(refresh_job_image_shell2)
          @menu_refresh.append(refresh_job_item_shell2)

          @menu_job.show_all          
          @menu_refresh.show_all          

          # TreeView Signals
          @treeview2.signal_connect('button_press_event') do |treeview, event|
            if event.kind_of? Gdk::EventButton
              if (event.button == 3)
                path, column, x, y = treeview.get_path_at_pos(event.x, event.y)

                begin
                  iter = @treeview2.model.get_iter(path)
                  treeview.selection.select_path(path)
                  @menu_job.popup(nil, nil, event.button, event.time)
                rescue
                  @menu_refresh.popup(nil, nil, event.button, event.time)
                end
              end
            end
          end

          # Menu Signals
          kill_job_item_shell.signal_connect('activate') do |item|
            if current = @selection.selected
              stop_job(current)
            end
          end

          refresh_job_item_shell.signal_connect('activate') do |item|
            refresh_job()
          end
          
          refresh_job_item_shell2.signal_connect('activate') do |item|
            refresh_job()
          end

        end # def initialize

        #
        # Add One Shot
        #
        def add_oneshot(id, name)
          oneshot_childiter = @model.append(@oneshot_iter)
          oneshot_childiter.set_value(JID, id.to_s)
          oneshot_childiter.set_value(NAME, name.split(":")[1])
          @treeview2.expand_all()
        end

        #
        # Stop job and and let the framework remove it from the job tree
        #
        def stop_job(iter)

          # Isolate the job ID
          jid = iter[JID]

          # Informing the user
          $gtk2driver.append_log_view("[*] Stopping exploit: #{iter[NAME]}\n")

          # Stopping job
          framework.jobs.stop_job(jid)
        end

        #
        # Refresh jobs tree
        #
        def refresh_job
          clear_tree()
          framework.jobs.keys.sort.each do |k|
            add_oneshot(framework.jobs[k].jid, framework.jobs[k].name)
          end
        end

        #
        # Remove job by id and remote it from jobs tree
        #
        def remove_job(id)
          found = nil
          @model.each do |model,path,iter|
            if (iter[JID] == id)
              found = iter
              break
            end
          end

          @model.remove(found) if found
        end

        protected

        #
        # Clear tree and add parents iter
        #
        def clear_tree
          @model.clear
          # Add AutoPWN
          #@autopwn_iter = @model.append(nil)
          #@autopwn_iter.set_value(PIX, driver.get_icon("menu_autopwn.xpm"))
          #@autopwn_iter.set_value(JID, "AutoPWN")

          # Add Parent "One shot"
          @oneshot_iter = @model.append(nil)
          @oneshot_iter.set_value(PIX, driver.get_icon("menu_oneshot.xpm"))
          @oneshot_iter.set_value(JID, "Jobs")
        end

      end

    end
  end
end
