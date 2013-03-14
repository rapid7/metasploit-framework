# encoding: utf-8

# Adapted from the rails3 compatibility shim in Haml 2.2
module Formtastic
  # @private
  module Util
    extend self
    ## Rails XSS Safety

    # Returns the given text, marked as being HTML-safe.
    # With older versions of the Rails XSS-safety mechanism,
    # this destructively modifies the HTML-safety of `text`.
    #
    # @param text [String]
    # @return [String] `text`, marked as HTML-safe
    def html_safe(text)
      if text.respond_to?(:html_safe)
        text.html_safe
      else
        text
      end
    end

  end
end
