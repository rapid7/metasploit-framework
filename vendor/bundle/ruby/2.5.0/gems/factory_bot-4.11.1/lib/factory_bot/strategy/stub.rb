module FactoryBot
  module Strategy
    class Stub
      @@next_id = 1000

      DISABLED_PERSISTENCE_METHODS = [
        :connection,
        :decrement!,
        :delete,
        :destroy!,
        :destroy,
        :increment!,
        :reload,
        :save!,
        :save,
        :toggle!,
        :touch,
        :update!,
        :update,
        :update_attribute,
        :update_attributes!,
        :update_attributes,
        :update_column,
        :update_columns,
      ].freeze

      def association(runner)
        runner.run(:build_stubbed)
      end

      def result(evaluation)
        evaluation.object.tap do |instance|
          stub_database_interaction_on_result(instance)
          clear_changed_attributes_on_result(instance)
          evaluation.notify(:after_stub, instance)
        end
      end

      private

      def next_id
        @@next_id += 1
      end

      def stub_database_interaction_on_result(result_instance)
        result_instance.id ||= next_id

        result_instance.instance_eval do
          def persisted?
            !new_record?
          end

          def new_record?
            id.nil?
          end

          def destroyed?
            nil
          end

          DISABLED_PERSISTENCE_METHODS.each do |write_method|
            define_singleton_method(write_method) do |*args|
              raise "stubbed models are not allowed to access the database - #{self.class}##{write_method}(#{args.join(",")})"
            end
          end
        end

        created_at_missing_default = result_instance.respond_to?(:created_at) && !result_instance.created_at

        if created_at_missing_default
          result_instance.instance_eval do
            def created_at
              @created_at ||= Time.now.in_time_zone
            end
          end
        end

        has_updated_at = result_instance.respond_to?(:updated_at)
        updated_at_no_default = has_updated_at && !result_instance.updated_at

        if updated_at_no_default
          result_instance.instance_eval do
            def updated_at
              @updated_at ||= Time.current
            end
          end
        end
      end

      def clear_changed_attributes_on_result(result_instance)
        unless result_instance.respond_to?(:clear_changes_information)
          result_instance.extend ActiveModelDirtyBackport
        end

        result_instance.clear_changes_information
      end
    end

    module ActiveModelDirtyBackport
      def clear_changes_information
        @previously_changed = ActiveSupport::HashWithIndifferentAccess.new
        @changed_attributes = ActiveSupport::HashWithIndifferentAccess.new
      end
    end
  end
end
