require 'spec_helper'
require 'msf/base/simple/auxiliary'
require 'msf/base/simple/noop_job_listener'

RSpec.describe Msf::Simple::Auxiliary, '#cleanup tracking' do
  let(:datastore) { double('Datastore', :[]= => nil, :[] => nil) }
  let(:events) { double('EventDispatcher', on_module_run: nil, on_module_complete: nil, on_session_module_run: nil) }
  let(:framework) { double('Framework', jobs: jobs, events: events) }
  let(:jobs) { double('JobManager') }
  let(:mod) do
    mod = double(
      'AuxiliaryModule',
      refname: 'scanner/test',
      framework: framework,
      datastore: datastore,
      setup: nil,
      cleanup: nil,
      print_error: nil,
      :error= => nil,
      actions: [],
      action: nil,
      passive?: false,
      validate: nil,
      run: nil,
      init_ui: nil,
      user_input: nil,
      report_failure: nil,
      user_output: nil,
      fail_reason: Msf::Module::Failure::None,
      print_status: nil,
      fail_detail: nil,
      _import_extra_options: nil,
      job_id: 1,
      :job_id= => nil,
      :run_uuid= => nil,
      run_uuid: nil
    )
    allow(mod).to receive(:replicant).and_return(mod)
    allow(mod).to receive(:extend)
    allow(mod).to receive(:fail_reason=)
    allow(mod).to receive(:fail_detail=)
    mod
  end

  before do
    allow(Msf::Simple::Framework).to receive(:simplify_module)
    require 'rex'
    require 'rex/text'
    allow(Rex).to receive(:sleep)
  end

  it 'run_simple runs successfully and receives only one cleanup call' do
    described_class.run_simple(mod)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple interrupts and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise ::Interrupt }
    described_class.run_simple(mod)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple raises StandardError and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise StandardError }
    described_class.run_simple(mod)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple raises Msf::Auxiliary::Complete and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise Msf::Auxiliary::Complete }
    described_class.run_simple(mod)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple raises Msf::Auxiliary::Failed and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise Msf::Auxiliary::Failed }
    described_class.run_simple(mod)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple raises ::Timeout::Error and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise ::Timeout::Error }
    described_class.run_simple(mod)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple raises ::Msf::OptionValidateError and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise ::Msf::OptionValidateError }
    described_class.run_simple(mod)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple receives double interrupt (force quit) and still receives one cleanup call' do
    allow(mod).to receive(:run) { raise ::Interrupt }
    allow(Rex).to receive(:sleep) { raise ::Interrupt }
    expect { described_class.run_simple(mod) }.to raise_error(::Interrupt)
    expect(mod).to have_received(:cleanup).once
  end

  it 'check_simple receives double interrupt (force quit) and still receives one cleanup call' do
    allow(mod).to receive(:has_check?).and_return(true)
    allow(mod).to receive(:check) { raise ::Interrupt }
    allow(Rex).to receive(:sleep) { raise ::Interrupt }
    expect { described_class.check_simple(mod, {}) }.to raise_error(::Interrupt)
    expect(mod).to have_received(:cleanup).once
  end

  it 'run_simple cleans up when the completion event raises' do
    allow(events).to receive(:on_module_complete).and_raise(StandardError)
    expect { described_class.run_simple(mod) }.to raise_error(StandardError)
    expect(mod).to have_received(:cleanup).once
  end

  it 'RunAsJob cleans up once after a handled failure' do
    allow(mod).to receive(:run) { raise Msf::Auxiliary::Failed }
    job_context = nil
    run_callback = nil
    cleanup_callback = nil
    allow(jobs).to receive(:start_bg_job) do |_name, context, run_proc, cleanup_proc|
      job_context = context
      run_callback = run_proc
      cleanup_callback = cleanup_proc
      1
    end

    described_class.run_simple(mod, 'RunAsJob' => true)
    run_callback.call(job_context)
    cleanup_callback.call(job_context)

    expect(mod).to have_received(:cleanup).once
  end
end
