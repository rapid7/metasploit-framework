# Outputs an `<input type="submit">` or `<input type="reset">` wrapped in the standard `<li>` 
# wrapper. This the default for `:submit` and `:reset` actions, but `:as => :button` is also 
# available as an alternative.
#
# @example The `:as` can be ommitted, these are functionally equivalent
#   <%= f.action :submit, :as => :input %>
#   <%= f.action :submit %>
#
# @example Full form context and output
#
#   <%= semantic_form_for(@post) do |f| %>
#     <%= f.actions do %>
#       <%= f.action :reset, :as => :input %>
#       <%= f.action :submit, :as => :input %>
#     <% end %>
#   <% end %>
#
#   <form...>
#     <fieldset class="actions">
#       <ol>
#         <li class="action input_action" id="post_reset_action">
#           <input type="reset" value="Reset">
#         </li>
#         <li class="action input_action" id="post_submit_action">
#           <input type="submit" value="Create Post">
#         </li>
#       </ol>
#     </fieldset>
#   </form>
#
# @example Specifying a label with a String
#   <%= f.action :submit, :as => :input, :label => "Go" %>
#
# @example Pass HTML attributes down to the `<input>`
#   <%= f.action :submit, :as => :input, :button_html => { :class => 'pretty', :accesskey => 'g', :disable_with => "Wait..." } %>
#
# @example Access key can also be set as a top-level option
#   <%= f.action :submit, :as => :input, :accesskey => 'g' %>
#
# @example Pass HTML attributes down to the `<li>` wrapper (classes are appended to the existing classes)
#   <%= f.action :submit, :as => :input, :wrapper_html => { :class => 'special', :id => 'whatever' } %>
#   <%= f.action :submit, :as => :input, :wrapper_html => { :class => ['extra', 'special'], :id => 'whatever' } %>
#
# @option *args :label [String, Symbol]
#   Override the label text with a String or a symbol for an i18n translation key
#
# @option *args :button_html [Hash]
#   Override or add to the HTML attributes to be passed down to the `<input>` tag
#
# @option *args :wrapper_html [Hash]
#   Override or add to the HTML attributes to be passed down to the wrapping `<li>` tag
#
# @todo document i18n keys
# @todo document i18n translation with :label (?)
module Formtastic
  module Actions
    class InputAction
      include Base
      include Buttonish
      
      def to_html
        wrapper do
          builder.submit(text, button_html)
        end
      end
    end
  end
end