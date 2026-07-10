# frozen_string_literal: true

require 'spec_helper'

# Framework-side smoke spec. Confirms the `metasploit_data_models`
# release that ships the reporting refactor's foundational tables is
# wired up correctly: the AR classes load, their tables exist, and
# the documented columns are present.
RSpec.describe 'Reporting schema presence', type: :model do
  describe 'Mdm::ModuleExecution' do
    subject(:klass) { Mdm::ModuleExecution }

    it 'is loadable as an ApplicationRecord descendant' do
      expect(klass.ancestors).to include(ApplicationRecord)
    end

    it 'is bound to the module_executions table' do
      expect(klass.table_name).to eq('module_executions')
      expect(ApplicationRecord.connection.table_exists?('module_executions')).to be(true)
    end

    it 'exposes the documented columns' do
      column_names = klass.column_names
      expect(column_names).to include(
        'id',
        'workspace_id',
        'module_reference_name',
        'module_type',
        'kind',
        'options_snapshot',
        'originating_interface',
        'originating_user_id',
        'originating_token_ref',
        'parent_execution_id',
        'started_at',
        'ended_at',
        'terminal_status',
        'failure_reason',
        'failure_message',
        'single_entity_failure_count',
        'last_single_entity_errors',
        'created_at',
        'updated_at'
      )
    end

    it 'exposes the documented enum constants' do
      expect(klass::KINDS).to match_array(%w[run check import direct_write])
      expect(klass::MODULE_TYPES).to match_array(
        %w[exploit auxiliary post payload encoder evasion nop external]
      )
      expect(klass::ORIGINATING_INTERFACES).to match_array(
        %w[console rpc json_rpc mcp external import plugin autocheck]
      )
      expect(klass::TERMINAL_STATUSES).to match_array(
        %w[running success neutral expected_failure unhandled_exception]
      )
    end

    it 'declares the documented associations' do
      assoc_names = klass.reflect_on_all_associations.map(&:name)
      expect(assoc_names).to include(
        :workspace,
        :originating_user,
        :parent_execution,
        :children,
        :execution_errors,
        :events
      )
    end
  end

  describe 'Mdm::ModuleExecutionError' do
    subject(:klass) { Mdm::ModuleExecutionError }

    it 'is loadable as an ApplicationRecord descendant' do
      expect(klass.ancestors).to include(ApplicationRecord)
    end

    it 'is bound to the module_execution_errors table' do
      expect(klass.table_name).to eq('module_execution_errors')
      expect(ApplicationRecord.connection.table_exists?('module_execution_errors')).to be(true)
    end

    it 'exposes the documented columns' do
      expect(klass.column_names).to include(
        'id',
        'module_execution_id',
        'exception_class',
        'message',
        'backtrace',
        'lifecycle_phase',
        'failure_reason',
        'occurred_at',
        'created_at'
      )
    end

    it 'exposes the lifecycle-phase enum constant' do
      expect(klass::LIFECYCLE_PHASES).to match_array(
        %w[setup check exploit cleanup post run]
      )
    end
  end

  describe 'Mdm::ModuleExecutionEvent' do
    subject(:klass) { Mdm::ModuleExecutionEvent }

    it 'is loadable as an ApplicationRecord descendant' do
      expect(klass.ancestors).to include(ApplicationRecord)
    end

    it 'is bound to the module_execution_events table' do
      expect(klass.table_name).to eq('module_execution_events')
      expect(ApplicationRecord.connection.table_exists?('module_execution_events')).to be(true)
    end

    it 'exposes the documented columns' do
      expect(klass.column_names).to include(
        'id',
        'module_execution_id',
        'name',
        'payload',
        'occurred_at',
        'created_at'
      )
    end
  end
end
