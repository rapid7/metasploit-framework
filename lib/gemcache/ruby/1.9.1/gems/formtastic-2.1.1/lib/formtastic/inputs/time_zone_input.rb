module Formtastic
  module Inputs

    # Outputs a `<label>` with a `<select>` containing a series of time zones (using Rails' own
    # `time_zone_select` helper), wrapped in the standard `<li>` wrapper.

    # This is the default input choice for attributes matching /time_zone/, but can be applied to
    # any text-like input with `:as => :time_zone`.
    #
    # @example Full form context and output
    #
    #   <%= semantic_form_for(@user) do |f| %>
    #     <%= f.inputs do %>
    #       <%= f.input :time_zone, :as => :time_zone %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="time_zone">
    #           <label for="user_time_zone">Time zone</label>
    #           <input type="text" id="user_time_zone" name="user[time_zone]">
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    #
    # @todo document :priority_zones option
    # @todo configurable default :priority_zones?
    class TimeZoneInput 
      include Base

      def to_html
        input_wrapping do
          label_html <<
          builder.time_zone_select(method, priority_zones, input_options, input_html_options)
        end
      end
      
      def priority_zones
        options[:priority_zones] || [] # TODO config?
      end
    end
  end
end