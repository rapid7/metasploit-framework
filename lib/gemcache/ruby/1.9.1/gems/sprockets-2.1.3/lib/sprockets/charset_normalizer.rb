require 'tilt'

module Sprockets
  # Some browsers have issues with stylesheets that contain multiple
  # `@charset` definitions. The issue surfaces while using Sass since
  # it inserts a `@charset` at the top of each file. Then Sprockets
  # concatenates them together.
  #
  # The `CharsetNormalizer` processor strips out multiple `@charset`
  # definitions.
  #
  # The current implementation is naive. It picks the first `@charset`
  # it sees and strips the others. This works for most people because
  # the other definitions are usually `UTF-8`. A more sophisticated
  # approach would be to re-encode stylesheets with mixed encodings.
  #
  # This behavior can be disabled with:
  #
  #     environment.unregister_bundle_processor 'text/css', Sprockets::CharsetNormalizer
  #
  class CharsetNormalizer < Tilt::Template
    def prepare
    end

    def evaluate(context, locals, &block)
      charset = nil

      # Find and strip out any `@charset` definitions
      filtered_data = data.gsub(/^@charset "([^"]+)";$/) {
        charset ||= $1; ""
      }

      if charset
        # If there was a charset, move it to the top
        "@charset \"#{charset}\";#{filtered_data}"
      else
        data
      end
    end
  end
end
