module Msf
  module Ui
    module Gtk2

      ##
      # This class describe all search stuff into the module treeview
      ##
      class ModuleSearch
        include Msf::Ui::Gtk2::MyControls

        RUNNING, CLEAR = *(0..2).to_a

        @@state = nil

        #
        # Initialize all stuff to perform a search
        #
        def initialize(search_entry, search_button, search_cancel_button)
          @search_entry = search_entry
          @search_button = search_button
          @cancel_button = search_cancel_button

          # Active completion
          completion()

          # Init state
          @@state = CLEAR

          # Signals
          @search_entry.signal_connect('activate') do
            @search_button.activate
          end

          @search_button.signal_connect('clicked') do
            if @search_entry.text.match(/[a-zA-Z0-9\(\)]/)
              search(@search_entry.text)
            end
          end

          @cancel_button.signal_connect('clicked') do
            cancel()
          end
        end


        #
        # Perform a search throught the module treeview,
        # and return the array result to MyModuleTree::remove
        #
        def search(text)
          # If current state set to RUUNING, call cancel method
          cancel if @@state == RUNNING

          # Set current state to RUNNING
          @@state = RUNNING

          # Perform the search
          found = []
          filter = Regexp.new(text, Regexp::IGNORECASE)
		  
		  $gtk2driver.module_tree.refresh(filter)
		  $gtk2driver.module_tree.expand
        end


        #
        # Clean the Gtk::Entry and refresh the modules treeview
        #
        def cancel
          # clear the Gtk::Entry
          @search_entry.set_text("")

          # Colorize the Gtk::Entry
          state(CLEAR)

          # Refresh the modules treeview
          $gtk2driver.module_tree.refresh

          # Register the current state
          @@state = CLEAR
        end


        #
        # Colorize the Gtk::Entry by state parameter
        #
        def state(state)
          if (state == RUNNING)
            @search_entry.modify_base(Gtk::STATE_NORMAL, Gdk::Color.parse('gray'))
          elsif (state == CLEAR)
            @search_entry.modify_base(Gtk::STATE_NORMAL, Gdk::Color.parse('white'))
          end
        end

        #
        # Display completion for @search_entry
        #
        def completion
          # set completion
          completion = Gtk::EntryCompletion.new
          @search_entry.completion = completion

          # Describe the model completion
          model = Gtk::ListStore.new(String)
          $gtk2driver.module_completion.each do |v|
            iter = model.append
            iter[0] = v
          end

          # Attach the model completion to the completion object
          completion.model = model
          completion.text_column = 0
        end
      end

    end
  end
end