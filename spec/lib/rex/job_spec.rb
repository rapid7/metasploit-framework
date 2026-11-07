require 'spec_helper'
require 'timeout'
require 'rex/thread_factory'
require 'rex/job'
require 'rex/job_container'

RSpec.shared_context 'Rex::Job thread fixtures' do
  subject(:job) { container.add_job('test job', context, run_proc, clean_proc) }

  let(:container) { Rex::JobContainer.new }
  let(:context) { Object.new }
  let(:threads) { [] }
  let(:release) { Queue.new }
  let(:entered) { Queue.new }
  let(:completed) { Queue.new }
  let(:run_calls) { Queue.new }
  let(:run_proc) { proc { run_calls << context } }
  let(:clean_proc) { proc { |ctx| completed << ctx } }
  let(:expected_thread_errors) { [] }
  let(:extra_gates) { [] }

  before do
    allow(Rex::ThreadFactory).to receive(:spawn) do |_name, _critical, &block|
      spawn_thread(&block)
    end
  end

  after do
    [release, *extra_gates].each { |gate| 4.times { gate << true } }
    # Stop every fixture before joining any of its possible dependencies.
    threads.select(&:alive?).each(&:kill)
    threads.each do |thread|
      join_thread(thread)
    rescue StandardError => e
      raise unless expected_thread_errors.include?([e.class, e.message])
    end
    expect(threads.none?(&:alive?)).to be(true)
  end

  def spawn_thread(&block)
    Thread.new(&block).tap do |thread|
      thread.report_on_exception = false
      threads << thread
    end
  end

  def await(queue)
    Timeout.timeout(3) { queue.pop }
  end

  def join_thread(thread)
    raise Timeout::Error, 'Job thread did not finish' unless thread.join(3)
  end
end

RSpec.describe Rex::Job do
  include_context 'Rex::Job thread fixtures'

  describe '#start' do
    it 'runs and cleans up the supplied context before removing a completed job' do
      worker = job.start(true)
      join_thread(worker)

      expect(await(run_calls)).to equal(context)
      expect(await(completed)).to equal(context)
      expect(container).to be_empty
    end

    context 'when the run procedure raises' do
      let(:run_proc) { proc { raise ArgumentError, 'Run failed' } }
      let(:expected_thread_errors) { [[ArgumentError, 'Run failed']] }

      it 'propagates the error after cleanup' do
        worker = job.start(true)

        expect { join_thread(worker) }.to raise_error(ArgumentError, 'Run failed')
        expect(await(completed)).to equal(context)
        expect(container).to be_empty
      end
    end

    context 'without a cleanup procedure' do
      let(:clean_proc) { nil }

      it 'removes the completed job' do
        join_thread(job.start(true))

        expect(container).to be_empty
      end
    end

    context 'when cleanup raises' do
      let(:expected_thread_errors) { [[ArgumentError, 'Cleanup failed']] }
      let(:clean_proc) do
        proc do |ctx|
          completed << ctx
          raise ArgumentError, 'Cleanup failed'
        end
      end

      it 'propagates the error without retrying the callback' do
        worker = job.start(true)

        expect { join_thread(worker) }.to raise_error(ArgumentError, 'Cleanup failed')
        expect(job.synchronized_cleanup).to be_nil
        expect(completed.size).to eq(1)
      end
    end

    context 'when cleanup uses a timeout' do
      let(:clean_proc) do
        proc do |ctx|
          Timeout.timeout(0.01) { release.pop }
        rescue Timeout::Error
          completed << ctx
        end
      end

      it 'allows the cleanup timeout to fire' do
        join_thread(job.start(true))

        expect(await(completed)).to equal(context)
      end
    end

    context 'when stopped before the factory starts the worker' do
      let(:factory_entered) { Queue.new }
      let(:factory_release) { Queue.new }
      let(:extra_gates) { [factory_release] }

      before do
        allow(Rex::ThreadFactory).to receive(:spawn) do |_name, _critical, &block|
          factory_entered << true
          factory_release.pop
          spawn_thread(&block)
        end
      end

      it 'does not run work after cleanup has already been claimed' do
        instance = job
        starter = spawn_thread { instance.start(true) }
        await(factory_entered)
        container.stop_job(instance.jid)
        factory_release << true
        join_thread(starter)
        threads.each { |thread| join_thread(thread) }

        expect(run_calls).to be_empty
        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    context 'when the worker runs before the factory returns' do
      let(:factory_release) { Queue.new }
      let(:extra_gates) { [factory_release] }
      let(:run_proc) do
        proc do
          entered << true
          release.pop
        end
      end

      before do
        allow(Rex::ThreadFactory).to receive(:spawn) do |_name, _critical, &block|
          spawn_thread(&block).tap { factory_release.pop }
        end
      end

      it 'can cancel the running worker before start returns' do
        instance = job
        starter = spawn_thread { instance.start(true) }
        await(entered)
        worker = (threads - [starter]).first
        container.stop_job(instance.jid)
        join_thread(worker)
        factory_release << true
        join_thread(starter)

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    context 'when the worker starts between the stop decision and cleanup claim' do
      let(:factory_entered) { Queue.new }
      let(:factory_release) { Queue.new }
      let(:before_claim) { Queue.new }
      let(:claim_release) { Queue.new }
      let(:extra_gates) { [factory_release, claim_release] }

      it 'does not admit work after the stop request' do
        instance = job
        allow(Rex::ThreadFactory).to receive(:spawn) do |_name, _critical, &block|
          factory_entered << true
          factory_release.pop
          spawn_thread(&block)
        end
        allow(instance).to receive(:synchronized_cleanup).and_wrap_original do |original|
          if Thread.current[:job_spec_stopper]
            before_claim << true
            claim_release.pop
          end
          original.call
        end

        starter = spawn_thread { instance.start(true) }
        await(factory_entered)
        stopper = spawn_thread do
          Thread.current[:job_spec_stopper] = true
          container.stop_job(instance.jid)
        end
        await(before_claim)
        factory_release << true
        join_thread(starter)
        (threads - [starter, stopper]).each { |worker| join_thread(worker) }
        claim_release << true
        join_thread(stopper)
        instance.stop

        expect(run_calls).to be_empty
        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end
  end
end

RSpec.describe Rex::Job do
  include_context 'Rex::Job thread fixtures'

  describe '#stop' do
    it 'cleans up an inline job once across repeated stops' do
      job.start(false)
      container.stop_job(job.jid)
      job.stop

      expect(completed.size).to eq(1)
      expect(container).to be_empty
    end

    context 'when an inline run raises' do
      let(:run_proc) { proc { raise ArgumentError, 'Inline run failed' } }

      it 'cleans up before propagating the error' do
        expect { job.start(false) }.to raise_error(ArgumentError, 'Inline run failed')
        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    context 'when called by the worker during its run procedure' do
      let(:run_proc) { proc { container.stop_job(job.jid) } }

      it 'unwinds cancellation before cleaning up' do
        join_thread(job.start(true))

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    context 'while the run procedure is blocked' do
      let(:run_proc) do
        proc do
          entered << true
          release.pop
        end
      end

      it 'interrupts the run procedure and cleans up once' do
        worker = job.start(true)
        await(entered)
        container.stop_job(job.jid)
        join_thread(worker)
        job.stop

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    context 'while cleanup is already running' do
      let(:clean_proc) do
        proc do |ctx|
          entered << true
          release.pop
          completed << ctx
        end
      end

      it 'returns without interrupting or waiting for the cleanup owner' do
        worker = job.start(true)
        await(entered)
        stopper = spawn_thread { container.stop_job(job.jid) }
        join_thread(stopper)
        expect(completed).to be_empty
        release << true
        join_thread(worker)

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end

      it 'allows cleanup to finish once after concurrent stop requests' do
        worker = job.start(true)
        await(entered)
        stoppers = Array.new(4) { spawn_thread { job.stop } }
        stoppers.each { |stopper| join_thread(stopper) }
        release << true
        join_thread(worker)

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    context 'when cleanup is called separately from the worker' do
      let(:run_proc) do
        proc do
          entered << true
          release.pop
        end
      end

      it 'still stops the worker after cleanup has completed' do
        worker = job.start(true)
        await(entered)
        job.synchronized_cleanup
        job.stop
        join_thread(worker)

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end

      context 'while the separate cleanup callback is blocked' do
        let(:cleanup_entered) { Queue.new }
        let(:cleanup_release) { Queue.new }
        let(:extra_gates) { [cleanup_release] }
        let(:clean_proc) do
          proc do |ctx|
            cleanup_entered << true
            cleanup_release.pop
            completed << ctx
          end
        end

        it 'stops the worker without waiting for the separate cleanup owner' do
          worker = job.start(true)
          await(entered)
          cleaner = spawn_thread { job.synchronized_cleanup }
          await(cleanup_entered)
          stopper = spawn_thread { container.stop_job(job.jid) }
          join_thread(stopper)
          join_thread(worker)
          expect(completed).to be_empty
          cleanup_release << true
          join_thread(cleaner)

          expect(completed.size).to eq(1)
          expect(container).to be_empty
        end
      end
    end

    context 'when the run procedure has already called cleanup' do
      let(:run_proc) do
        proc do
          job.synchronized_cleanup
          entered << true
          release.pop
        end
      end

      it 'does not treat completed cleanup as an active owner' do
        worker = job.start(true)
        await(entered)
        job.stop
        join_thread(worker)

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    context 'when cleanup called by the run procedure requests a stop' do
      let(:clean_proc) do
        proc do |ctx|
          container.stop_job(job.jid)
          completed << ctx
        end
      end
      let(:run_proc) do
        proc do
          job.synchronized_cleanup
          run_calls << context
        end
      end

      it 'finishes cleanup before unwinding the run procedure' do
        join_thread(job.start(true))

        expect(completed.size).to eq(1)
        expect(run_calls).to be_empty
        expect(container).to be_empty
      end
    end

    context 'when cleanup stops its own job' do
      let(:clean_proc) do
        proc do |ctx|
          container.stop_job(job.jid)
          completed << ctx
        end
      end

      it 'finishes cleanup without recursively locking or terminating itself' do
        join_thread(job.start(true))

        expect(completed.size).to eq(1)
        expect(container).to be_empty
      end
    end

    it 'allows reciprocal job stops from two cleanup callbacks to finish' do
      ready = Queue.new
      second = nil
      first = container.add_job('first', nil, proc {}, proc do
        ready << true
        release.pop
        container.stop_job(second.jid)
        completed << 'first'
      end)
      second = container.add_job('second', nil, proc {}, proc do
        ready << true
        release.pop
        container.stop_job(first.jid)
        completed << 'second'
      end)
      workers = [first.start(true), second.start(true)]
      2.times { await(ready) }
      2.times { release << true }
      workers.each { |worker| join_thread(worker) }

      expect(completed.size).to eq(2)
      expect(container).to be_empty
    end
  end

  describe '#synchronized_cleanup' do
    let(:clean_proc) { proc { :cleanup_result } }

    it 'returns the callback result only for the caller that claims cleanup' do
      expect(job.synchronized_cleanup).to eq(:cleanup_result)
      expect(job.synchronized_cleanup).to be_nil
    end
  end
end
