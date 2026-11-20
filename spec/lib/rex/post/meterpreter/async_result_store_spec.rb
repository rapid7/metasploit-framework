# frozen_string_literal: true

require 'rex/post/meterpreter/async_result_store'

RSpec.describe Rex::Post::Meterpreter::AsyncResultStore do
  let(:store) { described_class.new }

  before do
    allow(store).to receive(:dlog)
    allow(store).to receive(:elog)
  end

  it 'preserves pending and running entries when clearing terminal results' do
    store.queue('pending', 'pending')
    store.queue('running', 'running')
    store.mark_running('running')
    store.queue('complete', 'complete')
    store.complete('complete', nil)
    store.queue('cancelled', 'cancelled')
    store.cancel('cancelled')

    expect(store.clear_completed).to eq(2)
    expect(store.all.transform_values { |entry| entry[:status] }).to eq('pending' => :pending, 'running' => :running)
  end

  it 'cancels work queued behind the current command when stopped' do
    started = ::Queue.new
    store.enqueue_work('running', 'running') do |rid|
      started << true
      sleep 0.1
      store.complete(rid, nil)
    end
    store.enqueue_work('pending', 'pending') { |rid| store.complete(rid, nil) }
    started.pop

    store.stop_worker

    expect(store.fetch('running')[:status]).to eq(:cancelled)
    expect(store.fetch('pending')[:status]).to eq(:cancelled)
  end

  it 'starts a fresh worker after stopping' do
    first_done = ::Queue.new
    store.enqueue_work('first', 'first') do |rid|
      store.complete(rid, nil)
      first_done << true
    end
    first_done.pop
    store.stop_worker

    second_done = ::Queue.new
    store.enqueue_work('second', 'second') do |rid|
      store.complete(rid, nil)
      second_done << true
    end
    second_done.pop
    store.stop_worker

    expect(store.fetch('second')[:status]).to eq(:complete)
  end
end
