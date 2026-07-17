# frozen_string_literal: true

require 'spec_helper'
require 'msf/base/simple/post'
require 'msf/base/simple/noop_job_listener'

RSpec.describe Msf::Simple::Post, '#job_run_proc job tracking' do
  let(:run_uuid) { 'post-run-uuid' }
  let(:job_listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
  let(:events) { double('EventDispatcher', on_module_run: nil, on_module_complete: nil, on_session_module_run: nil) }
  let(:sessions) { double('SessionManager', get: session) }
  let(:session) { double('Session') }
  let(:framework) { double('Framework', events: events, sessions: sessions) }
  let(:datastore) { { 'SESSION' => 1 } }
  let(:mod) do
    double(
      'PostModule',
      framework: framework,
      datastore: datastore,
      setup: nil,
      cleanup: nil,
      print_error: nil,
      :error= => nil
    )
  end
  let(:ctx) { [mod, run_uuid, job_listener] }

  context 'when the module run succeeds' do
    it 'reports start then completed with the run result' do
      result = 'post-result'
      allow(mod).to receive(:run).and_return(result)
      described_class.job_run_proc(ctx)
      expect(job_listener).to have_received(:start).with(run_uuid)
      expect(job_listener).to have_received(:completed).with(run_uuid, result, mod)
      expect(job_listener).not_to have_received(:failed)
    end
  end

  context 'when the session is missing' do
    let(:session) { nil }
    it 'reports failed and does not invoke mod.run' do
      expect(mod).not_to receive(:run)
      described_class.job_run_proc(ctx)
      expect(job_listener).to have_received(:start).with(run_uuid)
      expect(job_listener).to have_received(:failed).with(run_uuid, kind_of(String), mod)
      expect(job_listener).not_to have_received(:completed)
    end
  end

  context 'when the module run raises' do
    it 'reports failed with the exception' do
      err = RuntimeError.new('post-boom')
      allow(mod).to receive(:run).and_raise(err)
      described_class.job_run_proc(ctx)
      expect(job_listener).to have_received(:start).with(run_uuid)
      expect(job_listener).to have_received(:failed).with(run_uuid, err, mod)
      expect(job_listener).not_to have_received(:completed)
    end
  end

  context 'when the module raises Msf::Post::Complete' do
    it 'reports completed via the listener' do
      allow(mod).to receive(:run).and_raise(Msf::Post::Complete)
      described_class.job_run_proc(ctx)
      expect(job_listener).to have_received(:completed).with(run_uuid, nil, mod)
    end
  end
end

RSpec.describe Msf::Simple::Post, '.run_simple' do
  let(:job_listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
  let(:datastore) { double('Datastore', :[]= => nil, :[] => nil) }
  let(:framework) { double('Framework', jobs: jobs) }
  let(:jobs) { double('JobManager') }
  let(:mod) do
    mod = double(
      'PostModule',
      replicant: nil,
      refname: 'multi/general/execute',
      framework: framework,
      datastore: datastore,
      actions: [],
      action: nil,
      passive?: true,
      validate: nil,
      init_ui: nil,
      user_input: nil,
      user_output: nil,
      _import_extra_options: nil,
      :job_id= => nil,
      job_id: 42,
      :run_uuid= => nil,
      run_uuid: nil
    )
    allow(mod).to receive(:replicant).and_return(mod)
    allow(mod).to receive(:extend)
    mod
  end

  before do
    allow(Msf::Simple::Framework).to receive(:simplify_module)
    allow(jobs).to receive(:start_bg_job).and_return(42)
    require 'rex/text'
  end

  it 'generates a run uuid, notifies the listener, and assigns mod.run_uuid / mod.job_id' do
    captured_uuid = nil
    expect(job_listener).to receive(:waiting) { |uuid| captured_uuid = uuid }
    expect(mod).to receive(:run_uuid=).with(kind_of(String)).at_least(:once)
    expect(mod).to receive(:job_id=).with(42).at_least(:once)

    described_class.run_simple(mod, { 'RunAsJob' => true }, job_listener: job_listener)

    expect(captured_uuid).to be_a(String)
    expect(captured_uuid.length).to be >= 8
  end
end
