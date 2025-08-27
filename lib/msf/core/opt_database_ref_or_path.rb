# -*- coding: binary -*-

module Msf
  ###
  #
  # Opt that can be reference a database Id or a file on disk; Valid examples:
  # - /tmp/foo.txt
  # - id:123
  ###
  class OptDatabaseRefOrPath < OptBase
    def normalize(value)
      return value if value.nil? || value.to_s.empty? || value.start_with?('id:')

      File.expand_path(value)
    end

    def validate_on_assignment?
      false
    end

    # Generally, 'value' should be a file that exists, or an integer database id.
    def valid?(value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)

      if value && !value.empty?
        if value.start_with?('id:')
          return value.match?(/^id:\d+$/)
        end

        unless File.exist?(File.expand_path(value))
          return false
        end
      end
      super
    end
  end
end
