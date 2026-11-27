require 'spec_helper'
require 'timeout'
require 'rex/text'
require 'msf/base/simple/auxiliary'
require 'msf/base/simple/post'
require 'msf/base/simple/exploit'
require 'msf/core/exploit_driver'
require 'msf/core/rpc/v10/rpc_job_status_tracker'
require 'rex/job'
require 'rex/job_container'

RSpec.describe Msf::RPC::RpcJobStatusTracker, 'queued job cancellation' do
  subject(:tracker) { described_class.new }
  let(:uuid) { 'queued-cancellation-fixture' }
  let(:mod) { double('Module') }

  before { tracker.waiting(uuid) }

  it 'stores an acknowledgeable error and removes the waiting entry' do
    tracker.cancelled_before_start(uuid, mod)

    expect(tracker.waiting_ids).to be_empty
    expect(tracker.result(uuid)).to eq('error' => 'Job cancelled before execution')
    expect(tracker.ack(uuid)).to be_truthy
    expect(tracker.result_ids).to be_empty
  end

  it 'leaves a running job unchanged' do
    tracker.start(uuid)
    tracker.cancelled_before_start(uuid, mod)

    expect(tracker).to be_running(uuid)
    expect(tracker).not_to be_finished(uuid)
  end

  it 'does not overwrite a completed result' do
    tracker.start(uuid)
    tracker.completed(uuid, 'original result', mod)
    tracker.cancelled_before_start(uuid, mod)

    expect(tracker.result(uuid)).to eq('result' => 'original result')
  end

  it 'does not overwrite a reported failure' do
    tracker.failed(uuid, 'original failure', mod)
    tracker.cancelled_before_start(uuid, mod)

    expect(tracker.waiting_ids).to be_empty
    expect(tracker.result(uuid)).to eq('error' => 'original failure')
  end

  it 'does not recreate an acknowledged failure reported before start' do
    tracker.failed(uuid, 'original failure', mod)
    tracker.ack(uuid)
    tracker.cancelled_before_start(uuid, mod)

    expect(tracker.waiting_ids).to be_empty
    expect(tracker.result_ids).to be_empty
  end

  it 'does not recreate an acknowledged cancellation result' do
    tracker.cancelled_before_start(uuid, mod)
    tracker.ack(uuid)
    tracker.cancelled_before_start(uuid, mod)

    expect(tracker.waiting_ids).to be_empty
    expect(tracker.result_ids).to be_empty
  end
end

RSpec.describe 'Module cleanup after queued cancellation' do
  let(:tracker) { Msf::RPC::RpcJobStatusTracker.new }
  let(:uuid) { 'module-cancellation-fixture' }
  let(:events) { double('Events', on_module_complete: nil) }
  let(:framework) { double('Framework', events: events) }
  let(:mod) { double('Module', framework: framework, cleanup: nil) }
  let(:payload) { double('Payload', stop_handler: nil) }

  shared_examples 'queued cleanup notification' do
    it 'finishes the waiting record when cleanup runs without execution' do
      tracker.waiting(uuid)
      cleanup.call(tracker)

      expect(tracker.waiting_ids).to be_empty
      expect(tracker.result(uuid)).to eq('error' => 'Job cancelled before execution')
    end

    it 'still reports cancellation when module cleanup raises' do
      tracker.waiting(uuid)
      allow(mod).to receive(:cleanup).and_raise(RuntimeError, 'cleanup failed')

      expect { cleanup.call(tracker) }.to raise_error(RuntimeError, 'cleanup failed')
      expect(tracker.waiting_ids).to be_empty
      expect(tracker).to be_finished(uuid)
    end

    it 'accepts an existing listener without the optional notification' do
      listener = double('LegacyJobListener')

      expect { cleanup.call(listener) }.not_to raise_error
      expect(mod).to have_received(:cleanup).once
    end
  end

  context 'auxiliary run and check' do
    let(:cleanup) { ->(listener) { Msf::Simple::Auxiliary.job_cleanup_proc([mod, uuid, listener]) } }
    include_examples 'queued cleanup notification'
  end

  context 'post run' do
    let(:cleanup) { ->(listener) { Msf::Simple::Post.job_cleanup_proc([mod, uuid, listener]) } }
    include_examples 'queued cleanup notification'
  end

  context 'exploit run' do
    let(:driver) { Msf::ExploitDriver.new(framework) }
    let(:cleanup) { ->(listener) { driver.send(:job_cleanup_proc, [mod, payload, uuid, listener]) } }
    include_examples 'queued cleanup notification'
  end
end

RSpec.describe Msf::Simple::Exploit, 'cancelled queued check' do
  let(:jobs) { Rex::JobContainer.new }
  let(:tracker) { Msf::RPC::RpcJobStatusTracker.new }
  let(:framework) { double('Framework', jobs: jobs) }
  let(:mod) do
    double(
      'Module',
      framework: framework, _import_extra_options: nil, validate: nil,
      has_check?: true, refname: 'cancelled-check-fixture', job_id: 0, :job_id= => nil
    )
  end

  it 'finishes the queued result without invoking setup or check' do
    entered = Queue.new
    release = Queue.new
    workers = Queue.new
    starter = worker = nil
    allow(mod).to receive(:replicant).and_return(mod)
    allow(Msf::Simple::Framework).to receive(:simplify_module)
    allow(Rex::ThreadFactory).to receive(:spawn) do |_name, _critical, &block|
      entered << true
      release.pop
      Thread.new(&block).tap { |spawned| workers << spawned }
    end
    response = nil
    starter = Thread.new do
      response = described_class.check_simple(mod, 'RunAsJob' => true, 'JobListener' => tracker)
    end
    starter.report_on_exception = false
    Timeout.timeout(3) { entered.pop }
    jobs.stop_job(jobs.keys.fetch(0))
    release << true
    raise Timeout::Error unless starter.join(3)

    worker = workers.pop
    raise Timeout::Error unless worker.join(3)

    uuid = response.first
    expect(jobs).to be_empty
    expect(tracker.waiting_ids).to be_empty
    expect(tracker.result(uuid)).to eq('error' => 'Job cancelled before execution')
  ensure
    4.times { release << true }
    fixtures = [starter, worker].compact
    fixtures << workers.pop until workers.empty?
    fixtures.uniq.select(&:alive?).each(&:kill)
    fixtures.uniq.each { |thread| raise Timeout::Error unless thread.join(3) }
  end
end
