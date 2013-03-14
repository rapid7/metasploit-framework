module Formtastic
  module Inputs

    # Outputs a simple `<label>` with a `<textarea>` wrapped in the standard
    # `<li>` wrapper. This is the default input choice for database columns of the `:text` type,
    # but can forced on any text-like input with `:as => :text`.
    #
    # @example Full form context and output
    #
    #   <%= semantic_form_for(@user) do |f| %>
    #     <%= f.inputs do %>
    #       <%= f.input :first_name, :as => :text %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="text">
    #           <label for="user_first_name">First name</label>
    #           <textarea cols="30" id="user_first_name" name="user[first_name]" rows="20"></textarea>
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    class TextInput 
      include Base
      include Base::Placeholder
      
      def input_html_options
        { 
          :cols => builder.default_text_area_width,
          :rows => builder.default_text_area_height
        }.merge(super)
      end
      
      def to_html
        input_wrapping do
          label_html <<
          builder.text_area(method, input_html_options)
        end
      end
    
    end
  end
end