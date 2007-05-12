module Msf
  module Ui
    module Gtk2

      #
      # Subclass the TreeViewTooltips to add our get_tooltip function
      #
      class AssistantTips < Msf::Ui::Gtk2::TreeViewTooltips

        def initialize(column)
          super()
          @column = column
        end

        def get_tooltip(view, column, path)
          if (column == @column)
            model = view.model
            iter = model.get_iter(path)
            return iter.get_value(3)
          end
        end
      end


      ##
      # This class perform an assistant to configure module
      ##
      class MsfAssistant

        KEY, DEFAULT, VALUE, DESC = *(0..5).to_a

        class Exploit < Msf::Ui::Gtk2::Assistant

          # to stock our values
          WIZARD = {}

          WizardStruct = Struct.new('Wizard',
          :description, :page,
          :target_state, :payload_state, :options_state, :review_state)

          ARRAY = [
            ['Target',
              ["Select your target", "intro", true, false, false, false],
            ],
            ['Payload',
              ["Select your payload", "payload", true, true, false, false],
            ],
            ['Options',
              ["Select your options", "option", true, true, true, false],
            ],
            ['Review',
              ["Check your review", "end", true, true, true, true],
            ],
          ].collect do |item, state|
            WIZARD[item] = WizardStruct.new(	state[0],
            state[1],
            state[2],
            state[3],
            state[4],
            state[5]
            )
          end

          #
          # Init
          #
          def initialize(active_module)
            @active_module = active_module
            @session_tree  = $gtk2driver.session_tree
            @job_tree   = $gtk2driver.job_tree
            @hash = {}

            # Call the parent
            super(@active_module.refname)

            # Initialize exploit driver's exploit instance
            @mydriver = Msf::ExploitDriver.new(framework)
            @mydriver.exploit = framework.exploits.create(@active_module.refname)

            # Main interface
            @model_required = Gtk::ListStore.new(String, String, String, String)
            @model_advanced = Gtk::ListStore.new(String, String, String, String)
            target_completion()

            # Build the left frame
            populate_frame(
            [
              @label_target = create_label(	WIZARD['Target'].target_state,
              WIZARD['Target'].description
              ),
              @label_payload = create_label(	WIZARD['Target'].payload_state,
              WIZARD['Payload'].description
              ),
              @label_options = create_label(	WIZARD['Target'].options_state,
              WIZARD['Options'].description
              ),
              @label_review = create_label(	WIZARD['Target'].review_state,
              WIZARD['Review'].description
              )
            ]
            )

            self.show_all
          end

          #
          # Save configuration for MsfAssistant
          #
          def save
            # Save the console config
            $gtk2driver.save_config(@mydriver.exploit)

            # Save the framework's datastore
            begin
              framework.save_config

              if (@mydriver.exploit)
                @mydriver.exploit.save_config
              end
            rescue
              MsfDialog::Error.new(self, "Failed to save config file")
              return false
            end

            $gtk2driver.append_log_view("Saved configuration to: #{Msf::Config.config_file}\n")
          end

          #
          # Action when Forward button was clicked
          #
          def next_page
            if (self.page == "intro")
              self.page = "payload"
              refresh_label(	[@label_target], 			# historic
              [@label_payload], 			# actual
              [@label_options, @label_review]	# next
              )
              display()
              payload_completion()
            elsif (self.page == "payload")
              self.page = "options"
              refresh_label(	[@label_target, @label_payload],	# historic
              [@label_options], 			# actual
              [@label_review]				# next
              )
              button_forward.set_sensitive(false)
              display()
              options_completion()
            elsif (self.page == "options")
              self.page = "end"
              refresh_label(	[@label_target, @label_payload, @label_options],
              [@label_review],
              nil
              )
              display()
              review_completion()
            end
          end

          #
          # Validate options in datastore
          #
          def validate
            errors = []
            @mydriver.exploit.datastore.import_options_from_hash(@hash)

            @mydriver.exploit.options.each_pair do |name, option|
              if (!option.valid?(@mydriver.exploit.datastore[name]))
                errors << name

                # If the option is valid, normalize its format to the correct type.
              elsif ((val = option.normalize(@mydriver.exploit.datastore[name])) != nil)
                @mydriver.exploit.datastore.update_value(name, val)
              end
            end

            if (errors.empty? == false)
              button_forward.set_sensitive(false)
              p errors.join(', ')
              # MsfDialog::Error.new(self, "Failed to validate : #{errors.join(', ')}")
            else
              button_forward.set_sensitive(true)
            end
          end

          #
          # Action when Back button was clicked
          #
          def back_page
            if (self.page == "payload")
              self.page = "intro"
              refresh_label(	nil,
              [@label_target],
              [@label_payload, @label_options, @label_review]
              )
              display()
              target_completion()
            elsif (self.page == "options")
              self.page = "payload"
              refresh_label(	[@label_target],			# historic
              [@label_payload], 			          # actual
              [@label_options, @label_review]	  # next
              )
              display()
              payload_completion()
            elsif (self.page == "end")
              self.page = "options"
              refresh_label(	[@label_target, @label_payload],
              [@label_options],
              [@label_review]
              )
              display()
              options_completion()
            end
          end

          #
          # Display the target view
          #
          def target_completion

            # Model for Gtk::Combo
            model_target = Gtk::ListStore.new(String, Object)

            # Add iter to Gtk::Combo
            @active_module.targets.each_with_index do |target, idx|
              iter = model_target.append
              iter[0] = target.name
              iter[1] = idx
            end

            # Gtk::ComboBox
            combo_target = Gtk::ComboBox.new(model_target)
            combo_target.active = 0

            # Pack & renderer combo_target
            renderer = Gtk::CellRendererText.new
            combo_target.pack_start(renderer, true)
            combo_target.set_attributes(renderer, :text => 0)

            # Define default value
            @hash["TARGET"] = combo_target.active_iter[1]

            # Signal for combo payload
            combo_target.signal_connect('changed') do ||
              @hash["TARGET"] = combo_target.active_iter[1]
            end

            self.main.pack_start(combo_target, true, false, 0)
            self.main.show_all
          end

          #
          # Display the payload view
          #
          def payload_completion

            # Model for Gtk::Combox
            model_all = Gtk::ListStore.new(String, Object)

            # Add iter to Model
            @active_module.compatible_payloads.each do |refname, payload|
              iter = model_all.append
              iter[0] = refname
              iter[1] = payload
            end

            # Gtk::ComboBox
            combo_all = Gtk::ComboBox.new(model_all)
            combo_all.active = 0

            # Pack & renderer combo_all
            renderer = Gtk::CellRendererText.new
            combo_all.pack_start(renderer, true)
            combo_all.set_attributes(renderer, :text => 0)

            # Pack combo
            self.main.pack_start(combo_all, true, false, 0)

            # Stuff for description payload
            textscroll = Gtk::ScrolledWindow.new
            textscroll.shadow_type = Gtk::SHADOW_IN
            textscroll.hscrollbar_policy = Gtk::POLICY_AUTOMATIC
            textscroll.vscrollbar_policy = Gtk::POLICY_AUTOMATIC
            buffer = Gtk::TextBuffer.new
            textview = Gtk::TextView.new(buffer)
            textview.set_editable(false)
            textview.set_cursor_visible(false)
            textscroll.add(textview)

            # Pack description
            self.main.pack_start(textscroll, true, false, 0)

            # Define default value
            buffer.set_text(combo_all.active_iter[1].new.description)
            @hash["PAYLOAD"] = combo_all.active_iter[0]

            # Signal for combo payload
            combo_all.signal_connect('changed') do
              buffer.set_text(combo_all.active_iter[1].new.description)
              @hash["PAYLOAD"] = combo_all.active_iter[0]
            end

            self.main.show_all
          end

          #
          # Display options view
          #
          def options_completion

            #
            @button_forward.set_sensitive(false)

            # Clear treeview
            @model_required.clear
            @model_advanced.clear

            # An expander view for advanced options
            frame_advanced = Gtk::Expander.new('Advanced')

            # TreeView
            @treeview_required = Gtk::TreeView.new(@model_required)
            @treeview_advanced = Gtk::TreeView.new(@model_advanced)

            # Column
            add_columns(@treeview_required, @model_required)
            add_columns(@treeview_advanced, @model_advanced)

            # Payload options
            @mydriver.payload = framework.payloads.create(@hash["PAYLOAD"])
            @mydriver.payload.options.each do |key, opt|
              if (opt.required?)
                pack(@model_required, key, opt)
              else
                pack(@model_advanced, key, opt)
              end
            end

            # Exploits options
            @mydriver.exploit.options.sorted.each do |key, opt|
              next if (opt.evasion?)
              if (opt.required?)
                pack(@model_required, key, opt)
              else
                pack(@model_advanced, key, opt)
              end
            end

            # add treeview to frame
            self.main.pack_start(@treeview_required, false, false, 0)
            self.main.pack_start(frame_advanced, false, false, 10)
            frame_advanced.add(@treeview_advanced)

            self.main.show_all
          end

          #
          # Display the review page
          #
          def review_completion
            warning = Gtk::Label.new
            warning.set_markup("Review your configuration before clicking the <b>apply</b> button")
            self.main.pack_start(warning, false, false, 0)

            label = Gtk::Label.new
            review = "\n\n"
            @hash.each do |key, value|
              review << "<b>#{key}</b> : #{value}\n"
            end
            label.set_markup(review)

            self.main.pack_start(label, false, false, 0)

            self.main.show_all
          end

          #
          # Add column and tips
          #
          def add_columns(treeview, model)
            # column for KEY
            renderer = Gtk::CellRendererText.new
            column = Gtk::TreeViewColumn.new('Name',
            renderer,
            'text' => KEY)
            column.set_sort_column_id(KEY)
            treeview.append_column(column)

            # column for DEFAULT
            renderer = Gtk::CellRendererText.new
            column = Gtk::TreeViewColumn.new('Default',
            renderer,
            'text' => DEFAULT)
            column.set_sort_column_id(DEFAULT)
            treeview.append_column(column)

            # column for VALUE
            renderer = Gtk::CellRendererText.new
            renderer.background = "#f6ffd6"
            renderer.editable = true
            renderer.signal_connect("edited") do |rend, path, text|
              updatevalue(model, VALUE, path, text)
            end
            column = Gtk::TreeViewColumn.new('Value',
            renderer,
            'text' => VALUE)
            column.set_sort_column_id(VALUE)
            column.set_resizable(true)
            treeview.append_column(column)

            # Init tips on the treeview
            tips = AssistantTips.new(column)
            tips.add_view(@treeview_required)
            tips.add_view(@treeview_advanced)
          end

          #
          # Display values on the treeview
          #
          def pack(model, key, opt)
            iter = model.append
            iter[KEY] = key
            if (key == "LHOST")
              iter[VALUE] = Rex::Socket.source_address
              @hash['LHOST'] = Rex::Socket.source_address
            end
            iter[DEFAULT] = opt.default.to_s
            iter[DESC] = opt.desc.to_s
          end

          #
          # Update changing value
          #
          def updatevalue(model, column, path, text)
            iter = model.get_iter(path)
            iter[column] = text
            @hash[iter.get_value(KEY)] = text
            validate()
          end

          #
          # Fire !!
          #
          def apply

            # Import options from the supplied assistant
            @mydriver.exploit.datastore.import_options_from_hash(@hash)

            # Share the exploit's datastore with the payload
            @mydriver.payload.share_datastore(@mydriver.exploit.datastore)

            @mydriver.target_idx = (@mydriver.exploit.datastore['TARGET']).to_i

            @pipe = Msf::Ui::Gtk2::GtkConsolePipe.new

            @mydriver.exploit.init_ui(@pipe, @pipe)
            @mydriver.payload.init_ui(@pipe, @pipe)

            # Session registration is done by event handler
            # XXX: No output from the exploit when this is set!
            @mydriver.use_job = true

            @pipe.create_subscriber_proc() do |msg|
              $stderr.puts "MSG: #{msg}"
              $gtk2driver.append_log_view(msg)
            end

            Thread.new do
              0.upto(20) do |i|
                $pipe.print_status("I am alive at #{i}")
                select(nil, nil, nil, 1.0)
              end
            end


            @pipe.print_status("Launching exploit #{@mydriver.exploit.refname}...")

            begin
              @mydriver.run
              @job_tree.add_oneshot(@active_module, @hash["RHOST"])
            rescue ::Exception => e
              @pipe.print_error("Exploit failed: #{e}")
            end
          end
        end

        class Auxiliary
        end

        class Payload
        end
      end

    end
  end
end
