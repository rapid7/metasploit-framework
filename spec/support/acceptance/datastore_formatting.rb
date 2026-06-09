# frozen_string_literal: true

module Acceptance
  # Shared helper for rendering datastore options as a command-line string
  # suitable for msfconsole. Used by both Target and Payload.
  module DatastoreFormatting
    # @param [Hash] module_datastore The merged datastore hash
    # @return [String] The formatted datastore options string
    def format_datastore_options(module_datastore)
      module_options = module_datastore.map do |key, value|
        value_str = value.to_s
        if value_str.match?(/[\s'"\\]/)
          escaped = value_str.gsub('"', '\\"')
          "#{key}=\"#{escaped}\""
        else
          "#{key}=#{value_str}"
        end
      end

      module_options.join(' ')
    end
  end
end
