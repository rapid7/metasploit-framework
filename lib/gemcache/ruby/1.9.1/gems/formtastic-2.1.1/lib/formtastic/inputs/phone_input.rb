module Formtastic
  module Inputs

    # Outputs a simple `<label>` with a HTML5 `<input type="phone">` wrapped in the standard
    # `<li>` wrapper. This is the default input choice for attributes with a name matching
    # `/(phone|fax)/`, but can be applied to any text-like input with `:as => :phone`.
    #
    # @example Full form context and output
    #
    #   <%= semantic_form_for(@user) do |f| %>
    #     <%= f.inputs do %>
    #       <%= f.input :mobile, :as => :phone %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="phone">
    #           <label for="user_mobile">Mobile</label>
    #           <input type="tel" id="user_mobile" name="user[mobile]">
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    class PhoneInput 
      include Base
      include Base::Stringish
      include Base::Placeholder
      
      def to_html
        input_wrapping do
          label_html <<
          builder.phone_field(method, input_html_options)
        end
      end
    end
    
  end
end