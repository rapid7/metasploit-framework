module Formtastic
  module Inputs

    # Outputs a simple `<label>` with a HTML5 `<input type="number">` wrapped in the standard
    # `<li>` wrapper. This is the default input choice for all database columns of the type `:float`
    # and `:decimal`, as well as `:integer` columns that aren't used for `belongs_to` associations,
    # but can be applied to any text-like input with `:as => :number`.
    #
    # Sensible default values for the `min`, `max` and `step` attributes are found by reflecting on 
    # the model's validations (when provided). An `IndeterminableMinimumAttributeError` exception 
    # will be raised when the following conditions are all true:
    #
    # * you haven't specified a `:min` or `:max` for the input
    # * the model's database column type is a `:float` or `:decimal`
    # * the validation uses `:less_than` or `:greater_than`
    #
    # The solution is to either:
    # 
    # * manually specify the `:min` or `:max` for the input
    # * change the database column type to an `:integer` (if appropriate)
    # * change the validations to use `:less_than_or_equal_to` or `:greater_than_or_equal_to`
    #
    # @example Full form context and output
    #
    #   <%= semantic_form_for(@user) do |f| %>
    #     <%= f.inputs do %>
    #       <%= f.input :shoe_size, :as => :number %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="numeric">
    #           <label for="user_shoe_size">Shoe size</label>
    #           <input type="number" id="user_shoe_size" name="user[shoe_size]">
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @example Default HTML5 min/max/step attributes are detected from the numericality validations
    #
    #   class Person < ActiveRecord::Base
    #     validates_numericality_of :age, 
    #       :less_than_or_equal_to => 100, 
    #       :greater_than_or_equal_to => 18, 
    #       :only_integer => true
    #   end
    #
    #   <%= f.input :age, :as => :number %>
    #
    #   <li class="numeric">
    #     <label for="persom_age">Age</label>
    #     <input type="number" id="person_age" name="person[age]" min="18" max="100" step="1">
    #   </li>
    #
    # @example Pass attributes down to the `<input>` tag with :input_html
    #  <%= f.input :shoe_size, :as => :number, :input_html => { :min => 3, :max => 15, :step => 1, :class => "special" } %>
    #
    # @example Min/max/step also work as options
    #  <%= f.input :shoe_size, :as => :number, :min => 3, :max => 15, :step => 1, :input_html => { :class => "special" } %>
    #
    # @example Use :in with a Range as a shortcut for :min/:max
    #  <%= f.input :shoe_size, :as => :number, :in => 3..15, :step => 1 %>
    #  <%= f.input :shoe_size, :as => :number, :input_html => { :in => 3..15, :step => 1 } %>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    # @see http://api.rubyonrails.org/classes/ActiveModel/Validations/HelperMethods.html#method-i-validates_numericality_of Rails' Numericality validation documentation
    class NumberInput 
      include Base
      include Base::Numeric
      include Base::Placeholder
      
      def to_html
        input_wrapping do
          label_html <<
          builder.number_field(method, input_html_options)
        end
      end

      def step_option
        super || "any"
      end

    end
  end
end