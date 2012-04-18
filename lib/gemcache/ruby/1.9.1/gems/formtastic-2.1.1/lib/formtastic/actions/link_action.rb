# Outputs a link wrapped in the standard `<li>` wrapper. This the default for `:cancel` actions.
# The link's URL defaults to Rails' built-in `:back` macro (the HTTP referrer, or Javascript for the
# browser's history), but can be altered with the `:url` option.
#
# @example The `:as` can be ommitted, these are functionally equivalent
#   <%= f.action :cancel, :as => :link %>
#   <%= f.action :cancel %>
#
# @example Full form context and output
#
#   <%= semantic_form_for(@post) do |f| %>
#     <%= f.actions do %>
#       <%= f.action :submit, :as => :input %>
#       <%= f.action :cancel, :as => :link %>
#     <% end %>
#   <% end %>
#
#   <form...>
#     <fieldset class="actions">
#       <ol>
#         <li class="action input_action" id="post_submit_action">
#           <input type="submit" value="Create Post">
#         </li>
#         <li class="action link_action" id="post_cancel_action">
#           <a href="javascript:history.back()">Cancel</a>
#         </li>
#       </ol>
#     </fieldset>
#   </form>
#
# @example Modifying the URL for the link
#   <%= f.action :cancel, :as => :link, :url => "http://example.com/path" %>
#   <%= f.action :cancel, :as => :link, :url => "/path" %>
#   <%= f.action :cancel, :as => :link, :url => posts_path %>
#   <%= f.action :cancel, :as => :link, :url => url_for(...) %>
#   <%= f.action :cancel, :as => :link, :url => { :controller => "posts", :action => "index" } %>
#
# @example Specifying a label with a String
#   <%= f.action :cancel, :as => :link, :label => "Stop" %>
#
# @example Pass HTML attributes down to the `<a>`
#   <%= f.action :cancel, :as => :link, :button_html => { :class => 'pretty', :accesskey => 'x' } %>
#
# @example Access key can also be set as a top-level option
#   <%= f.action :cancel, :as => :link, :accesskey => 'x' %>
#
# @example Pass HTML attributes down to the `<li>` wrapper (classes are appended to the existing classes)
#   <%= f.action :cancel, :as => :link, :wrapper_html => { :class => 'special', :id => 'whatever' } %>
#   <%= f.action :cancel, :as => :link, :wrapper_html => { :class => ['extra', 'special'], :id => 'whatever' } %>
#
# @option *args :label [String, Symbol]
#   Override the label text with a String or a symbol for an i18n translation key
#
# @option *args :button_html [Hash]
#   Override or add to the HTML attributes to be passed down to the `<a>` tag
#
# @option *args :wrapper_html [Hash]
#   Override or add to the HTML attributes to be passed down to the wrapping `<li>` tag
#
# @todo document i18n keys
# @todo document i18n translation with :label (?)
# @todo :prefix and :suffix options? (can also be done with CSS or subclassing for custom Actions)
module Formtastic
  module Actions
    class LinkAction

      include Base
      
      def supported_methods
        [:cancel]
      end
      
      # TODO reset_action class?
      def to_html
        wrapper do
          template.link_to(text, url, button_html)
        end
      end
      
      def url
        return options[:url] if options.key?(:url)
        :back
      end

    end
  end
end
