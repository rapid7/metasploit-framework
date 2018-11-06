module RSpec
  module Rails
    # @private
    # Disable some cops until https://github.com/bbatsov/rubocop/issues/1310
    # rubocop:disable Style/IndentationConsistency
    module FeatureCheck
    # rubocop:disable Style/IndentationWidth
    module_function
      # rubocop:enable Style/IndentationWidth

      def can_check_pending_migrations?
        has_active_record_migration? &&
          ::ActiveRecord::Migration.respond_to?(:check_pending!)
      end

      def can_maintain_test_schema?
        has_active_record_migration? &&
          ::ActiveRecord::Migration.respond_to?(:maintain_test_schema!)
      end

      def has_active_job?
        defined?(::ActiveJob)
      end

      def has_active_record?
        defined?(::ActiveRecord)
      end

      def has_active_record_migration?
        has_active_record? && defined?(::ActiveRecord::Migration)
      end

      def has_action_mailer?
        defined?(::ActionMailer)
      end

      def has_action_mailer_preview?
        has_action_mailer? && defined?(::ActionMailer::Preview)
      end

      def has_action_mailer_show_preview?
        has_action_mailer_preview? &&
          ::ActionMailer::Base.respond_to?(:show_previews=)
      end

      def has_1_9_hash_syntax?
        ::Rails::VERSION::STRING > '4.0'
      end

      def has_file_fixture?
        ::Rails::VERSION::STRING > '5.0'
      end

      def type_metatag(type)
        if has_1_9_hash_syntax?
          "type: :#{type}"
        else
          ":type => :#{type}"
        end
      end
    end
    # rubocop:enable Style/IndentationConsistency
  end
end
