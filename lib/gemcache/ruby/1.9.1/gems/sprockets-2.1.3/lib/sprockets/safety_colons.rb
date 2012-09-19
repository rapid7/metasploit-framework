require 'tilt'

module Sprockets
  # For JS developers who are colonfobic, concatenating JS files using
  # the module pattern usually leads to syntax errors.
  #
  # The `SafetyColons` processor will insert missing semicolons to the
  # end of the file.
  #
  # This behavior can be disabled with:
  #
  #     environment.unregister_postprocessor 'application/javascript', Sprockets::SafetyColons
  #
  class SafetyColons < Tilt::Template
    def prepare
    end

    def evaluate(context, locals, &block)
      # If the file is blank or ends in a semicolon, leave it as is
      if data =~ /\A\s*\Z/m || data =~ /;\s*\Z/m
        data
      else
        # Otherwise, append a semicolon and newline
        "#{data};\n"
      end
    end
  end
end
