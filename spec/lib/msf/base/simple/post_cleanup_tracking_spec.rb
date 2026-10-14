# frozen_string_literal: true

require 'spec_helper'
require 'msf/base/simple/post'
require 'msf/base/simple/noop_job_listener'

RSpec.describe Msf::Simple::Post, '#cleanup tracking' do
  let(:job_listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
  let(:datastore) { double('Datastore', :[]= => nil, :[] => nil) }
  let(:events) { double('EventDispatcher', on_module_run: nil, on_module_complete: nil, on_session_module_run: nil) }
  let(:sessions) { double('SessionManager', get: session) }
  let(:session) { double('Session') }
  let(:framework) { double('Framework', jobs: jobs, events: events, sessions: sessions) }
  let(:jobs) { double('JobManager') }
  let(:mod) do
    mod = double(
      'PostModule',
      framework: framework,
      datastore: datastore,
      setup: nil,
      cleanup: nil ,
      print_error: nil,
      :error= => nil,
      actions: [],
      action: nil,
      passive?: false,
      validate: nil,
      run: nil,
      cleanup: nil,
      init_ui: nil,
      user_input: nil,
      user_output: nil,
      _import_extra_options: nil,
      :run_uuid= => nil,
      run_uuid: nil
    )
    allow(mod).to receive(:replicant).and_return(mod)
    allow(mod).to receive(:extend)
    mod
  end

  before do
    allow(Msf::Simple::Framework).to receive(:simplify_module)
    require 'rex/text'
  end

  it 'run_simple runs successfully and receives only one cleanup call' do
    described_class.run_simple(mod, { 'RunAsJob' => false, 'JobListener' => job_listener })
    expect(mod).to have_received(:cleanup).once
  end
  
  it 'run_simple interrupts and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise ::Interrupt }
    described_class.run_simple(mod, { 'RunAsJob' => false, 'JobListener' => job_listener })
    expect(mod).to have_received(:cleanup).once
  end
  
  it 'run_simple raises Exception and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise ::Exception }
    described_class.run_simple(mod, { 'RunAsJob' => false, 'JobListener' => job_listener })
    expect(mod).to have_received(:cleanup).once
  end
  
  it 'run_simple raises Msf::Post::Complete and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise Msf::Post::Complete }
    described_class.run_simple(mod, { 'RunAsJob' => false, 'JobListener' => job_listener })
    expect(mod).to have_received(:cleanup).once
  end
  
  it 'run_simple raises Msf::Post::Failed and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise Msf::Post::Failed }
    described_class.run_simple(mod, { 'RunAsJob' => false, 'JobListener' => job_listener })
    expect(mod).to have_received(:cleanup).once
  end
  
  it 'run_simple raises ::Timeout::Error and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise ::Timeout::Error }
    described_class.run_simple(mod, { 'RunAsJob' => false, 'JobListener' => job_listener })
    expect(mod).to have_received(:cleanup).once
  end
  
  it 'run_simple raises ::Msf::OptionValidateError and receives only one cleanup call' do
    allow(mod).to receive(:run) { raise ::Msf::OptionValidateError }
    described_class.run_simple(mod, { 'RunAsJob' => false, 'JobListener' => job_listener })
    expect(mod).to have_received(:cleanup).once
  end

end

