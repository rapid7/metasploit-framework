module Msf
  module Ui
    module Gtk2

      ###
      #
      # This class provides an assistant to configure module
      #
      ###
      class MsfAssistant

        ###
        #
        # This class provides an assistant to configure auxiliary module
        #
        ###
        class Auxiliary < Msf::Ui::Gtk2::Assistant

          # to stock our values
          WIZARD2 = {}

          WizardStruct2 = Struct.new('Wizard2', :description, :page, :options_state, :review_state)

          ARRAY2 = [
            ['Options',
              ["Select your options", "option", true, true, true, false],
            ],
            ['Review',
              ["Confirm settings", "end", true, true, true, true],
            ],
          ].collect do |item, state|
            WIZARD2[item] = WizardStruct2.new(
            state[0],
            state[1],
            state[2],
            state[3]
            )
          end

          include Msf::Ui::Gtk2::MyControls

          def initialize(active_module)
            @active_module = active_module

            @job_tree   = $gtk2driver.job_tree
            @hash = {}

            # Call the parent
            super(@active_module.name)

            # Initialize exploit driver's exploit instance
            @mydriver = $gtk2driver
            @mydriver.exploit = framework.auxiliary.create(@active_module.refname)
            @mydriver.active_module = @active_module

			initialize_options()

			
            # Begin the wizard
            options_completion()

            # Build the left frame
            populate_frame(
            [
              @label_options = create_label(	WIZARD2['Options'].options_state,
              WIZARD2['Options'].description
              ),
              @label_review = create_label(	WIZARD2['Review'].review_state,
              WIZARD2['Review'].description
              )
            ]
            )

            self.show_all
          end

          #
          # Save configuration for MsfAssistant
          #
          def save
            dump_to_hash()

            @mydriver.exploit.datastore.import_options_from_hash(@hash, imported = false)

            # TODO: choose the $gtk2driver or @mydriver.exploit ?
            $gtk2driver.active_module = @mydriver.exploit
            $gtk2driver.save_config

            # Save the framework's datastore
            framework.save_config
            @mydriver.exploit.datastore.to_file(Msf::Config.config_file,  @mydriver.exploit.refname)
			MsfDialog::Information.new(self, 
				"Configuration Saved", 
				"Settings for auxiliary module #{@mydriver.exploit.refname} have been saved to #{Msf::Config.config_file}. " +
				"These settings will be loaded the next time this module is accessed."
			)
			
            $gtk2driver.append_log_view("Saved configuration to: #{Msf::Config.config_file}\n")
          end

          #
          # Action when Forward button was clicked
          #
          def next_page
            if (self.page == "options")
              if not validate()
                self.page = "options"
                refresh_label(	nil,	# historic
                [@label_options], 			# actual
                [@label_review]				# next
                )
                display()
				initialize_options()
                options_completion()
              else
                self.page = "end"
                refresh_label(	[@label_options],
                [@label_review],
                nil
                )
                display()
				initialize_options()
                review_completion()
              end
            end
          end

          #
          # Action when Back button was clicked
          #
          def back_page
            if (self.page == "end")
              self.page = "options"
              refresh_label(	nil,
              [@label_options],
              [@label_review]
              )
              display()
              options_completion()
            end
          end

		#
		# Instantiate the options page controls
		#
		def initialize_options
			@frame_standard = Gtk::Expander.new("Standard")
			@frame_advanced = Gtk::Expander.new("Advanced")
			@frame_evasion  = Gtk::Expander.new("Evasion")
			@options_standard = Gtk::VBox.new(false, 0)
			@options_advanced = Gtk::VBox.new(false, 0)
			@options_evasion  = Gtk::VBox.new(false, 0)

			@framer   = Gtk::VBox.new(false, 10)
			@scroller = Gtk::ScrolledWindow.new
			@scroller.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC) 
			@scroller.set_size_request(580, 420)

			@viewport = Gtk::Viewport.new(@scroller.hadjustment, @scroller.vadjustment)

			@frame_standard.expanded = true	
		end
		
		#
		# Display options view
		#
		def options_completion
			self.page = "options"

			# Title and three sets of options
			title = Gtk::Label.new
			title.set_markup("<big><b>#{@mydriver.exploit.name}</b></big>")
			@framer.pack_start(title, false, true, 5)	
			@framer.pack_start(@frame_standard, false, false, 10)
			@framer.pack_start(@frame_advanced, false, false, 10)
			@framer.pack_start(@frame_evasion, false, false, 10)

			# Standard options
			@mydriver.exploit.options.sorted.each do |key, opt|
				next if (opt.evasion?)
				next if (opt.advanced?)
				@options_standard.pack_start(add_option(key, opt, @mydriver.exploit.datastore[key]), false, false, 10)
			end

			# Advanced options
			@mydriver.exploit.options.sorted.each do |key, opt|
				next if (!opt.advanced?)
				@options_advanced.pack_start(add_option(key, opt, @mydriver.exploit.datastore[key]), false, false, 10)
			end

			# Evasion options
			@mydriver.exploit.options.sorted.each do |key, opt|
				next if (!opt.evasion?)
				@options_evasion.pack_start(add_option(key, opt, @mydriver.exploit.datastore[key]), false, false, 10)
			end

			# Display
			indent = Gtk::HBox.new(false, 5)
			indent.pack_start(Gtk::Label.new(""), false, false, 5)
			indent.pack_start(@options_standard, false, false, 0)
			indent.pack_start(Gtk::Label.new(""),true, true, 5)
			@frame_standard.add(indent)

			indent = Gtk::HBox.new(false, 5)
			indent.pack_start(Gtk::Label.new(""), false, false, 5)
			indent.pack_start(@options_advanced, false, false, 0)
			indent.pack_start(Gtk::Label.new(""),true, true, 5)
			@frame_advanced.add(indent)

			indent = Gtk::HBox.new(false, 5)				
			indent.pack_start(Gtk::Label.new(""), false, false, 5)				
			indent.pack_start(@options_evasion, false, false, 0)			
			indent.pack_start(Gtk::Label.new(""),true, true, 5)						
			@frame_evasion.add(indent)

			labels = ["Standard", "Advanced", "Evasion"]
			[@frame_standard, @frame_advanced, @frame_evasion].each do |obj|
				txt = labels.shift
				obj.spacing = 10
				obj.use_markup = true
				obj.label = "<big><b>#{txt}</b></big>"
			end

			# Stuff it into a viewport
			@viewport.add(@framer)

			# Stuff the viewport into a scrolledwindow
			@scroller.add(@viewport)

			# Stuff this into main and call it done
			self.main.pack_start(@scroller, true, true, 10)	
			self.main.show_all
		end

          #
          # Put all values in a hash
          #
          def dump_to_hash
            @options_standard.each do |widget|
              name, value = widget.get_pair
              begin
                if (@mydriver.exploit.options[name].default.to_s == value)
                  nil
                else
                  @hash[name] = value
                end
              rescue
                nil
              end
            end

            @options_advanced.each do |widget|
              name, value = widget.get_pair
              begin
                if (@mydriver.exploit.options[name].default.to_s == value)
                  nil
                else
                  @hash[name] = value
                end
              rescue
                nil
              end
            end

            @options_evasion.each do |widget|
              name, value = widget.get_pair
              begin
                if (@mydriver.exploit.options[name].default.to_s == value)
                  nil
                else
                  @hash[name] = value
                end
              rescue
                nil
              end
            end
          end

          #
          # Validate options in datastore
          #
          def validate
            dump_to_hash()

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
              MsfDialog::Error.new(self, "Failed to validate: #{errors.join(', ')}")
              false
            else
              true
            end
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
              review << "<b>#{key}</b>: #{value}\n"
            end
            label.set_markup(review)

            self.main.pack_start(label, false, false, 0)

            self.main.show_all
          end

          #
          # Fire !!
          #
          def apply

            # Import options from the supplied assistant
            @mydriver.exploit.datastore.import_options_from_hash(@hash)
            
            result = MsfWindow::Auxiliary.new(@mydriver.active_module.fullname, @hash)

            action  = @mydriver.exploit.datastore['ACTION']
            jobify  = true

            @pipe = Msf::Ui::Gtk2::GtkConsolePipe.new

            @pipe.create_subscriber_proc() do |msg|
              $gtk2driver.append_log_view(@mydriver.exploit.refname.split("/")[-1] + " " + msg)
              result.append_log_view(msg)
            end

            @pipe.print_status("Launching auxiliary #{@mydriver.exploit.refname}...")  
	
            begin
              Thread.new do
                @mydriver.exploit.run_simple(
                'Action'        => action,
                'Options'       => @hash,
                'LocalInput'    => @pipe,
                'LocalOutput'   => @pipe,
                'RunAsJob'      => jobify
                )		
              end
                
              result.show_all
            rescue ::Exception => e
              select(nil, nil, nil, 0.01)		
              return false
            end
          end
          
        end # MsfAssistant::Auxiliary

      end # Auxiliary

    end
  end
end
