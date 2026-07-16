# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Reporting::Execution do
  let(:datastore) { { 'RHOSTS' => '192.0.2.10', 'RPORT' => 80 } }
  let(:mod) do
    instance_double(
      'Msf::Module',
      fullname: 'exploit/windows/smb/ms17_010_eternalblue',
      refname: 'windows/smb/ms17_010_eternalblue',
      type: 'exploit',
      datastore: datastore
    )
  end
  let(:workspace) { double('workspace', id: 7) }
  let(:db) { double('db', active: true, workspace: workspace) }
  let(:framework) { double('framework', db: db) }

  describe '.start!' do
    let(:execution_row) { double('execution_row', id: 99) }

    it 'creates a row in the running state with captured attributes' do
      expect(::Mdm::ModuleExecution).to receive(:create!).with(
        hash_including(
          workspace: workspace,
          module_reference_name: 'exploit/windows/smb/ms17_010_eternalblue',
          module_type: 'exploit',
          kind: 'run',
          options_snapshot: datastore,
          originating_interface: 'console',
          parent_execution_id: nil,
          terminal_status: 'running',
          single_entity_failure_count: 0
        )
      ).and_return(execution_row)

      expect(
        described_class.start!(framework: framework, mod: mod, originating_interface: 'console')
      ).to be(execution_row)
    end

    it 'passes the supplied kind, parent, and started_at through' do
      now = Time.utc(2025, 1, 2, 3, 4, 5)
      expect(::Mdm::ModuleExecution).to receive(:create!).with(
        hash_including(
          kind: 'check',
          parent_execution_id: 42,
          started_at: now
        )
      ).and_return(execution_row)

      described_class.start!(
        framework: framework,
        mod: mod,
        originating_interface: :rpc,
        parent_execution_id: 42,
        kind: 'check',
        started_at: now
      )
    end

    it 'returns nil and warns when create! raises' do
      allow(::Mdm::ModuleExecution).to receive(:create!).and_raise(StandardError, 'db down')
      expect(described_class).to receive(:wlog).with(/failed to create ModuleExecution/)
      expect(
        described_class.start!(framework: framework, mod: mod, originating_interface: 'console')
      ).to be_nil
    end

    it 'returns nil when no workspace can be resolved' do
      empty_db = double('db', active: true, workspace: nil)
      empty_framework = double('framework', db: empty_db)
      expect(::Mdm::ModuleExecution).not_to receive(:create!)
      expect(
        described_class.start!(framework: empty_framework, mod: mod, originating_interface: 'console')
      ).to be_nil
    end

    it 'returns nil when the framework db is inactive' do
      inactive_db = double('db', active: false)
      inactive_framework = double('framework', db: inactive_db)
      expect(::Mdm::ModuleExecution).not_to receive(:create!)
      expect(
        described_class.start!(framework: inactive_framework, mod: mod, originating_interface: 'console')
      ).to be_nil
    end
  end

  describe '.finalize!' do
    it 'is a no-op when execution is nil' do
      expect(described_class.finalize!(nil, terminal_status: 'success')).to be_nil
    end

    it 'updates the row with ended_at and status' do
      execution = double('execution_row', id: 12)
      ended = Time.utc(2025, 6, 1, 0, 0, 0)
      expect(execution).to receive(:update!).with(
        ended_at: ended,
        terminal_status: 'expected_failure',
        failure_reason: 'no-target',
        failure_message: 'no target reached',
        check_code: nil,
        check_message: nil
      )
      described_class.finalize!(
        execution,
        terminal_status: 'expected_failure',
        failure_reason: 'no-target',
        failure_message: 'no target reached',
        ended_at: ended
      )
    end

    it 'stores check_code and check_message when supplied' do
      execution = double('execution_row', id: 13)
      ended = Time.utc(2025, 6, 1, 0, 0, 0)
      expect(execution).to receive(:update!).with(
        ended_at: ended,
        terminal_status: 'neutral',
        failure_reason: nil,
        failure_message: nil,
        check_code: 'safe',
        check_message: 'nothing here'
      )
      described_class.finalize!(
        execution,
        terminal_status: 'neutral',
        check_code: Msf::Exploit::CheckCode::Safe,
        check_message: 'nothing here',
        ended_at: ended
      )
    end

    it 'accepts a bare string for check_code' do
      execution = double('execution_row', id: 14)
      ended = Time.utc(2025, 6, 1, 0, 0, 0)
      expect(execution).to receive(:update!).with(
        hash_including(check_code: 'vulnerable', check_message: nil)
      )
      described_class.finalize!(
        execution,
        terminal_status: 'success',
        check_code: 'vulnerable',
        ended_at: ended
      )
    end

    it 'rescues update errors and warns' do
      execution = double('execution_row', id: 5)
      allow(execution).to receive(:update!).and_raise(StandardError, 'boom')
      expect(described_class).to receive(:wlog).with(/failed to finalize ModuleExecution #5/)
      expect(described_class.finalize!(execution, terminal_status: 'success')).to be(execution)
    end
  end

  describe '.capture_options_snapshot' do
    it 'returns the datastore as a hash' do
      expect(described_class.capture_options_snapshot(mod)).to eq(datastore)
    end

    it 'returns nil when the module has no datastore' do
      bare = double('mod', datastore: nil)
      expect(described_class.capture_options_snapshot(bare)).to be_nil
    end

    it 'returns nil when the datastore raises' do
      bad = double('mod')
      allow(bad).to receive(:datastore).and_raise(StandardError)
      expect(described_class.capture_options_snapshot(bad)).to be_nil
    end
  end

  describe '.terminal_status_for_check_code' do
    {
      'vulnerable' => 'success',
      'appears' => 'success',
      'safe' => 'neutral',
      'detected' => 'neutral',
      'unknown' => 'neutral',
      'unsupported' => 'neutral',
      nil => 'neutral'
    }.each do |code, expected|
      it "maps CheckCode #{code.inspect} to #{expected}" do
        cc = double('CheckCode', code: code)
        expect(described_class.terminal_status_for_check_code(cc)).to eq(expected)
      end
    end

    it 'is neutral when given a value that does not respond to #code' do
      expect(described_class.terminal_status_for_check_code(:safe)).to eq('neutral')
    end
  end
end
