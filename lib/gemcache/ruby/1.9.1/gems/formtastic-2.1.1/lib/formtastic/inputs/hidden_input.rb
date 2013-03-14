module Formtastic
  module Inputs

    # Outputs a simple `<input type="hidden">` wrapped in the standard `<li>` wrapper. This is
    # provided for situations where a hidden field needs to be rendered in the flow of a form with
    # many inputs that form an `<ol>`. Wrapping the hidden input inside the `<li>` maintains the
    # HTML validity. The `<li>` is marked with a `class` of `hidden` so that stylesheet authors can
    # hide these list items with CSS (formtastic.css does this out of the box).
    #
    # @example Full form context, output and CSS
    #
    #   <%= semantic_form_for(@something) do |f| %>
    #     <%= f.inputs do %>
    #       <%= f.input :secret, :as => :hidden %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="hidden">
    #           <input type="hidden" id="something_secret" name="something[secret]">
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    #   form.formtastic li.hidden { display:none; }
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    class HiddenInput 
      include Base
      
      # Override to include :value set directly from options hash. The :value set in :input_html 
      # hash will be preferred over :value set directly in the options.
      #
      # @todo this is inconsistent with all other inputs, deprecate and remove
      def input_html_options
        options.slice(:value).merge(super).merge(:required => nil).merge(:autofocus => nil)
      end
      
      def to_html
        input_wrapping do
          builder.hidden_field(method, input_html_options)
        end
      end
      
      def error_html
        ""
      end
      
      def errors?
        false
      end
      
      def hint_html
        ""
      end
      
      def hint?
        false
      end

    end
  end
end