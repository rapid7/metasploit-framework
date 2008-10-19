module Msf
  module Ui
    module Gtk2

      #
      #
      #
      class SkeletonType < Gtk::VBox
        
        attr_reader :key

        def initialize(key, opt, store)
          super(false, 0)
          
          @key = key
          
          pack_description(opt.desc.to_s)
          pack_option(opt.default.to_s, store)
          
        end

        #
        # Pack the description
        #
        def pack_description(description)
          label = Gtk::Label.new
          label.set_alignment(0, 1)
          label.set_markup("<b>#{@key}</b> : <i>#{description}</i>")
          self.pack_start(label, false, false, 0)
        end
        
        #
        # Dummy function, must be implemented by the subclass
        #
        def pack_option(default, store)
          raise NotImplementedError, "Subclass must implement pack_option"
        end

      end

    end
  end
end