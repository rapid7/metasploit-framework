# Outputs a `<button type="submit">` or `<button type="reset">` wrapped in the standard `<li>` 
# wrapper. This is an alternative choice for `:submit` and `:reset` actions, which render with 
# `<input type="submit">` and `<input type="reset">` by default.
#
# @example Full form context and output
#
#   <%= semantic_form_for(@post) do |f| %>
#     <%= f.actions do %>
#       <%= f.action :reset, :as => :button %>
#       <%= f.action :submit, :as => :button %>
#     <% end %>
#   <% end %>
#
#   <form...>
#     <fieldset class="actions">
#       <ol>
#         <li class="action button_action" id="post_reset_action">
#           <button type="reset" value="Reset">
#         </li>
#         <li class="action button_action" id="post_submit_action">
#           <button type="submit" value="Create Post">
#         </li>
#       </ol>
#     </fieldset>
#   </form>
#
# @example Specifying a label with a String
#   <%= f.action :submit, :as => :button, :label => "Go" %>
#
# @example Pass HTML attributes down to the `<button>`
#   <%= f.action :submit, :as => :button, :button_html => { :class => 'pretty', :accesskey => 'g', :disable_with => "Wait..." } %>
#
# @example Access key can also be set as a top-level option
#   <%= f.action :submit, :as => :button, :accesskey => 'g' %>
#
# @example Pass HTML attributes down to the `<li>` wrapper (classes are appended to the existing classes)
#   <%= f.action :submit, :as => :button, :wrapper_html => { :class => 'special', :id => 'whatever' } %>
#   <%= f.action :submit, :as => :button, :wrapper_html => { :class => ['extra', 'special'], :id => 'whatever' } %>
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
    class ButtonAction
      include Base
      include Buttonish
      
      # TODO absolutely horrible hack to work-around Rails < 3.1 missing button_tag, need
      # to figure out something more appropriate.
      #
      # TODO reset_action class?
      def to_html
        wrapper do
          if template.respond_to?(:button_tag)
            template.button_tag(text, button_html)
          else
            template.content_tag(:button, text, button_html)
          end
        end
      end
    end
  end
end