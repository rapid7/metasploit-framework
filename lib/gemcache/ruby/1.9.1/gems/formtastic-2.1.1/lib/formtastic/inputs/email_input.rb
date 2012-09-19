module Formtastic
  module Inputs

    # Outputs a simple `<label>` with a HTML5 `<input type="email">` wrapped in the standard
    # `<li>` wrapper. This is the default input choice for attributes with a name matching
    # `/email/`, but can be applied to any text-like input with `:as => :email`.
    #
    # @example Full form context and output
    #
    #   <%= semantic_form_for(@user) do |f| %>
    #     <%= f.inputs do %>
    #       <%= f.input :email_address, :as => :email %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="email">
    #           <label for="user_email_address">Email address</label>
    #           <input type="email" id="user_email_address" name="user[email_address]">
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    class EmailInput 
      include Base
      include Base::Stringish
      include Base::Placeholder
      
      def to_html
        input_wrapping do
          label_html <<
          builder.email_field(method, input_html_options)
        end
      end
    end
  end
end