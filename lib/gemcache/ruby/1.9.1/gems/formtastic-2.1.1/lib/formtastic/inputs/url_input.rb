module Formtastic
  module Inputs

    # Outputs a simple `<label>` with a HTML5 `<input type="url">` wrapped in the standard
    # `<li>` wrapper. This is the default input choice for all attributes matching
    # `/^url$|^website$|_url$/`, but can be applied to any text-like input with `:as => :url`.
    #
    # @example Full form context and output
    #
    #   <%= semantic_form_for(@user) do |f| %>
    #     <%= f.inputs do %>
    #       <%= f.input :home_page, :as => :url %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="url">
    #           <label for="user_home_page">Home page</label>
    #           <input type="number" id="user_home_page" name="user[home_page]">
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    class UrlInput 
      include Base
      include Base::Stringish
      include Base::Placeholder
      
      def to_html
        input_wrapping do
          label_html <<
          builder.url_field(method, input_html_options)
        end
      end
    end
  end
end