require 'spec_helper'
require 'msf/core/payload_generator'

describe Msf::PayloadGenerator do

  PAYLOAD_FRAMEWORK = Msf::Simple::Framework.create(
      :module_types => [  ::Msf::MODULE_PAYLOAD, ::Msf::MODULE_ENCODER, ::Msf::MODULE_NOP],
      'DisableDatabase' => true,
      'DisableLogging' => true
  )

  let(:lhost) { "192.168.172.1"}
  let(:lport) { "8443" }
  let(:datastore) { { "LHOST" => lhost, "LPORT" => lport } }
  let(:add_code) { false }
  let(:arch) { "x86" }
  let(:badchars) { '' }
  let(:encoder)  { '' }
  let(:format) { "raw" }
  let(:framework) { PAYLOAD_FRAMEWORK }
  let(:iterations) { 1 }
  let(:keep) { false }
  let(:nops) { 0 }
  let(:payload) { "windows/meterpreter/reverse_tcp"}
  let(:platform) { "Windows" }
  let(:space) { 1073741824 }
  let(:template) { File.join(Msf::Config.data_directory, "templates", "template_x86_windows.exe") }
  let(:generator_opts) {
    {
        add_code: add_code,
        arch: arch,
        badchars: badchars,
        encoder: encoder,
        datastore: datastore,
        format: format,
        framework: framework,
        iterations: iterations,
        keep: keep,
        nops: nops,
        payload: payload,
        platform: platform,
        space: space,
        template: template
    }
  }

  subject(:payload_generator) { described_class.new(generator_opts) }

  it { should respond_to :add_code }
  it { should respond_to :arch }
  it { should respond_to :badchars }
  it { should respond_to :encoder }
  it { should respond_to :datastore }
  it { should respond_to :format }
  it { should respond_to :framework }
  it { should respond_to :iterations }
  it { should respond_to :keep }
  it { should respond_to :nops }
  it { should respond_to :payload }
  it { should respond_to :platform }
  it { should respond_to :space }
  it { should respond_to :template }


end