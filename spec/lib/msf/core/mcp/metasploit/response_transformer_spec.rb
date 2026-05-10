# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Metasploit::ResponseTransformer do
  describe '.transform_modules' do
    it 'transforms valid module array' do
      modules = [
        {
          'name' => 'ms17_010_eternalblue',
          'fullname' => 'exploit/windows/smb/ms17_010_eternalblue',
          'type' => 'exploit',
          'rank' => 'excellent',
          'disclosuredate' => '2017-03-14',
          'description' => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption'
        }
      ]

      result = described_class.transform_modules(modules)

      expect(result).to be_an(Array)
      expect(result.length).to eq(1)
      expect(result[0]).to include(
        name: 'ms17_010_eternalblue',
        fullname: 'exploit/windows/smb/ms17_010_eternalblue',
        type: 'exploit',
        rank: 'excellent',
        disclosure_date: '2017-03-14'
      )
      # Note: description is not included in transform_modules output
    end

    it 'handles nil input' do
      expect(described_class.transform_modules(nil)).to eq([])
    end

    it 'handles empty array' do
      expect(described_class.transform_modules([])).to eq([])
    end

    it 'handles modules with missing fields' do
      modules = [{ 'name' => 'test', 'type' => 'exploit' }]
      result = described_class.transform_modules(modules)

      expect(result[0]).to include(name: 'test', type: 'exploit')
      expect(result[0]).not_to have_key(:description)
    end

    it 'uses fullname as name if name is missing' do
      modules = [{ 'fullname' => 'exploit/test', 'type' => 'exploit' }]
      result = described_class.transform_modules(modules)

      expect(result[0][:name]).to eq('exploit/test')
    end
  end

  describe '.transform_module_info' do
    let(:module_info) do
      {
        'type' => 'exploit',
        'name' => 'ms17_010_eternalblue',
        'fullname' => 'exploit/windows/smb/ms17_010_eternalblue',
        'rank' => 'excellent',
        'disclosuredate' => '2017-03-14',
        'description' => 'Test description',
        'license' => 'MSF_LICENSE',
        'filepath' => '/opt/metasploit-framework/modules/exploits/windows/smb/ms17_010.rb',
        'arch' => ['x64', 'x86'],
        'platform' => ['windows'],
        'authors' => ['Author 1', 'Author 2'],
        'privileged' => true,
        'check' => true,
        'default_options' => { 'Option1' => 'Value1' },
        'references' => [{'CVE' => '2017-0144'}, {'URL' => 'https://example.com'}],
        'targets' => { 0 => 'Windows 7', 1 => 'Windows 8' },
        'default_target' => 0,
        'stance' => 'aggressive',
        'actions' => { 0 => 'Action1', 1 => 'Action2' },
        'default_action' => 1,
        'options' => { 'RHOST' => '127.0.0.1', 'RPORT' => 445 }
      }
    end

    it 'transforms complete module info' do
      result = described_class.transform_module_info(module_info)

      expect(result).to include(
        type: 'exploit',
        name: 'ms17_010_eternalblue',
        fullname: 'exploit/windows/smb/ms17_010_eternalblue',
        rank: 'excellent',
        disclosure_date: '2017-03-14',
        description: 'Test description',
        license: 'MSF_LICENSE',
        filepath: 'modules/exploits/windows/smb/ms17_010.rb',
        architectures: ['x64', 'x86'],
        platforms: ['windows'],
        authors: ['Author 1', 'Author 2'],
        privileged: true,
        has_check_method: true,
        default_options: { 'Option1' => 'Value1' },
        references: [{'CVE' => '2017-0144'}, {'URL' => 'https://example.com'}],
        targets: { 0 => 'Windows 7', 1 => 'Windows 8' },
        default_target: 0,
        stance: 'aggressive',
        actions: { 0 => 'Action1', 1 => 'Action2' },
        default_action: 1,
        options: { 'RHOST' => '127.0.0.1', 'RPORT' => 445 }
      )
    end

    it 'transforms references array' do
      result = described_class.transform_module_info(module_info)

      expect(result[:references]).to be_an(Array)
      # Note: references are passed through as-is, not transformed to {type:, value:} format
      expect(result[:references]).to eq([
        {'CVE' => '2017-0144'},
        {'URL' => 'https://example.com'}
      ])
    end

    it 'handles nil input' do
      expect(described_class.transform_module_info(nil)).to eq({})
    end

    it 'handles empty hash' do
      expect(described_class.transform_module_info({})).to eq({})
    end

    it 'compacts nil values' do
      minimal_info = { 'name' => 'test', 'filepath' => 'modules/exploits/test.rb' }
      result = described_class.transform_module_info(minimal_info)

      expect(result[:name]).to eq('test')
      expect(result[:filepath]).to eq('modules/exploits/test.rb')
      expect(result).not_to have_key(:description)
    end

    it 'strips the install path prefix from filepath' do
      info = { 'name' => 'test', 'filepath' => '/home/user/.msf4/modules/post/linux/gather/enum_configs.rb' }
      result = described_class.transform_module_info(info)

      expect(result[:filepath]).to eq('modules/post/linux/gather/enum_configs.rb')
    end

    it 'handles nil filepath via safe navigation' do
      info = { 'name' => 'test', 'filepath' => nil }
      result = described_class.transform_module_info(info)

      expect(result).not_to have_key(:filepath)
    end

    it 'passes through filepath that already starts with modules/' do
      info = { 'name' => 'test', 'filepath' => 'modules/exploits/test.rb' }
      result = described_class.transform_module_info(info)

      expect(result[:filepath]).to eq('modules/exploits/test.rb')
    end
  end

  describe '.transform_hosts' do
    let(:hosts_response) do
      {
        'hosts' => [
          {
            'address' => '192.168.1.100',
            'mac' => '00:11:22:33:44:55',
            'name' => 'testhost',
            'os_name' => 'Linux',
            'os_flavor' => 'Ubuntu',
            'os_sp' => '20.04',
            'os_lang' => 'English',
            'purpose' => 'server',
            'info' => 'Web server',
            'state' => 'alive',
            'created_at' => 1609459200,
            'updated_at' => 1640995200
          }
        ]
      }
    end

    it 'transforms hosts with timestamps' do
      result = described_class.transform_hosts(hosts_response)

      expect(result).to be_an(Array)
      expect(result.length).to eq(1)
      expect(result[0]).to include(
        address: '192.168.1.100',
        mac_address: '00:11:22:33:44:55',
        hostname: 'testhost',
        os_name: 'Linux',
        os_flavor: 'Ubuntu',
        state: 'alive'
      )
      expect(result[0][:created_at]).to eq('2021-01-01T00:00:00Z')
      expect(result[0][:updated_at]).to eq('2022-01-01T00:00:00Z')
    end

    it 'handles nil input' do
      expect(described_class.transform_hosts(nil)).to eq([])
    end

    it 'handles missing hosts array' do
      expect(described_class.transform_hosts({})).to eq([])
    end

    it 'handles empty hosts array' do
      expect(described_class.transform_hosts({ 'hosts' => [] })).to eq([])
    end

    it 'handles hosts with missing fields' do
      minimal_response = { 'hosts' => [{ 'address' => '192.168.1.1' }] }
      result = described_class.transform_hosts(minimal_response)

      expect(result[0]).to eq({ address: '192.168.1.1' })
    end

    it 'handles nil timestamps' do
      response = { 'hosts' => [{ 'address' => '192.168.1.1', 'created_at' => nil }] }
      result = described_class.transform_hosts(response)

      expect(result[0]).not_to have_key(:created_at)
    end

    it 'handles zero timestamps' do
      response = { 'hosts' => [{ 'address' => '192.168.1.1', 'created_at' => 0 }] }
      result = described_class.transform_hosts(response)

      expect(result[0]).not_to have_key(:created_at)
    end
  end

  describe '.transform_services' do
    let(:services_response) do
      {
        'services' => [
          {
            'host' => '192.168.1.100',
            'port' => 80,
            'proto' => 'tcp',
            'state' => 'open',
            'name' => 'http',
            'info' => 'Apache httpd 2.4.41',
            'created_at' => 1609459200,
            'updated_at' => 1640995200
          }
        ]
      }
    end

    it 'transforms services' do
      result = described_class.transform_services(services_response)

      expect(result).to be_an(Array)
      expect(result[0]).to include(
        host_address: '192.168.1.100',
        port: 80,
        protocol: 'tcp',
        state: 'open',
        name: 'http',
        info: 'Apache httpd 2.4.41'
      )
    end

    it 'handles nil input' do
      expect(described_class.transform_services(nil)).to eq([])
    end

    it 'handles empty services array' do
      expect(described_class.transform_services({ 'services' => [] })).to eq([])
    end
  end

  describe '.transform_vulns' do
    let(:vulns_response) do
      {
        'vulns' => [
          {
            'host' => '192.168.1.100',
            'port' => 445,
            'proto' => 'tcp',
            'name' => 'MS17-010',
            'info' => 'SMB vulnerability',
            'refs' => 'CVE-2017-0144,MSB-2017-010',
            'time' => 1609459200
          }
        ]
      }
    end

    it 'transforms vulnerabilities' do
      result = described_class.transform_vulns(vulns_response)

      expect(result).to be_an(Array)
      expect(result[0]).to include(
        host: '192.168.1.100',
        port: 445,
        protocol: 'tcp',
        name: 'MS17-010'
      )
      expect(result[0][:references]).to eq(['CVE-2017-0144', 'MSB-2017-010'])
      expect(result[0][:created_at]).to eq('2021-01-01T00:00:00Z')
      # Note: 'info' field is not included in transform_vulns output
    end

    it 'handles nil input' do
      expect(described_class.transform_vulns(nil)).to eq([])
    end

    it 'handles empty vulns array' do
      expect(described_class.transform_vulns({ 'vulns' => [] })).to eq([])
    end

    it 'handles nil refs' do
      response = { 'vulns' => [{ 'host' => '192.168.1.1', 'refs' => nil }] }
      result = described_class.transform_vulns(response)

      expect(result[0]).not_to have_key(:refs)
    end

    it 'handles empty refs string' do
      response = { 'vulns' => [{ 'host' => '192.168.1.1', 'refs' => '' }] }
      result = described_class.transform_vulns(response)

      expect(result[0]).not_to have_key(:refs)
    end
  end

  describe '.transform_notes' do
    let(:notes_response) do
      {
        'notes' => [
          {
            'host' => '192.168.1.100',
            'service' => 'http',
            'type' => 'web.form',
            'data' => 'Login form found',
            'critical' => false,
            'seen' => true,
            'time' => 1609459200
          }
        ]
      }
    end

    it 'transforms notes' do
      result = described_class.transform_notes(notes_response)

      expect(result).to be_an(Array)
      expect(result[0]).to include(
        host: '192.168.1.100',
        service_name_or_port: 'http',
        note_type: 'web.form',
        data: 'Login form found'
      )
      expect(result[0][:created_at]).to eq('2021-01-01T00:00:00Z')
      # Note: 'critical' and 'seen' fields are not included in transform_notes output
    end

    it 'handles nil input' do
      expect(described_class.transform_notes(nil)).to eq([])
    end

    it 'handles empty notes array' do
      expect(described_class.transform_notes({ 'notes' => [] })).to eq([])
    end

    it 'handles ntype as fallback for type' do
      response = { 'notes' => [{ 'host' => '192.168.1.1', 'ntype' => 'test' }] }
      result = described_class.transform_notes(response)

      expect(result[0][:note_type]).to eq('test')
    end
  end

  describe '.transform_creds' do
    let(:creds_response) do
      {
        'creds' => [
          {
            'host' => '192.168.1.100',
            'port' => 22,
            'proto' => 'tcp',
            'sname' => 'ssh',
            'user' => 'admin',
            'pass' => 'password123',
            'type' => 'password',
            'updated_at' => 1609459200
          }
        ]
      }
    end

    it 'transforms credentials' do
      result = described_class.transform_creds(creds_response)

      expect(result).to be_an(Array)
      expect(result[0]).to include(
        host: '192.168.1.100',
        port: 22,
        protocol: 'tcp',
        service_name: 'ssh',
        user: 'admin',
        secret: 'password123',
        type: 'password'
      )
      expect(result[0][:updated_at]).to eq('2021-01-01T00:00:00Z')
    end

    it 'handles nil input' do
      expect(described_class.transform_creds(nil)).to eq([])
    end

    it 'handles empty creds array' do
      expect(described_class.transform_creds({ 'creds' => [] })).to eq([])
    end
  end

  describe '.transform_loot' do
    let(:loot_response) do
      {
        'loots' => [
          {
            'host' => '192.168.1.100',
            'service' => 'http',
            'ltype' => 'credentials',
            'ctype' => 'text/plain',
            'name' => 'passwords.txt',
            'info' => 'Recovered passwords',
            'data' => 'user1:pass1',
            'created_at' => 1609459200,
            'updated_at' => 1640995200
          }
        ]
      }
    end

    it 'transforms loot' do
      result = described_class.transform_loot(loot_response)

      expect(result).to be_an(Array)
      expect(result[0]).to include(
        host: '192.168.1.100',
        service_name_or_port: 'http',
        loot_type: 'credentials',
        content_type: 'text/plain',
        name: 'passwords.txt',
        info: 'Recovered passwords',
        data: 'user1:pass1'
      )
      expect(result[0][:created_at]).to eq('2021-01-01T00:00:00Z')
      expect(result[0][:updated_at]).to eq('2022-01-01T00:00:00Z')
    end

    it 'handles nil input' do
      expect(described_class.transform_loot(nil)).to eq([])
    end

    it 'handles empty loots array' do
      expect(described_class.transform_loot({ 'loots' => [] })).to eq([])
    end
  end

  describe '.format_timestamp' do
    it 'converts Unix epoch to ISO 8601' do
      timestamp = 1609459200 # 2021-01-01 00:00:00 UTC
      result = described_class.send(:format_timestamp, timestamp)

      expect(result).to eq('2021-01-01T00:00:00Z')
    end

    it 'handles nil' do
      expect(described_class.send(:format_timestamp, nil)).to be_nil
    end

    it 'handles zero' do
      expect(described_class.send(:format_timestamp, 0)).to be_nil
    end

    it 'handles string timestamps' do
      result = described_class.send(:format_timestamp, '1609459200')
      expect(result).to eq('2021-01-01T00:00:00Z')
    end
  end

  describe '.transform_references' do
    it 'transforms array of arrays' do
      refs = [['CVE', '2017-0144'], ['URL', 'https://example.com']]
      result = described_class.send(:transform_references, refs)

      expect(result).to eq([
        { type: 'CVE', value: '2017-0144' },
        { type: 'URL', value: 'https://example.com' }
      ])
    end

    it 'handles nil' do
      expect(described_class.send(:transform_references, nil)).to be_nil
    end

    it 'handles empty array' do
      expect(described_class.send(:transform_references, [])).to eq([])
    end

    it 'passes through malformed references' do
      refs = ['invalid', { type: 'custom' }]
      result = described_class.send(:transform_references, refs)

      expect(result).to eq(['invalid', { type: 'custom' }])
    end
  end

  describe '.parse_refs' do
    it 'parses comma-separated string' do
      refs = 'CVE-2017-0144,MS17-010,OSVDB-12345'
      result = described_class.send(:parse_refs, refs)

      expect(result).to eq(['CVE-2017-0144', 'MS17-010', 'OSVDB-12345'])
    end

    it 'strips whitespace' do
      refs = 'CVE-2017-0144, MS17-010 , OSVDB-12345'
      result = described_class.send(:parse_refs, refs)

      expect(result).to eq(['CVE-2017-0144', 'MS17-010', 'OSVDB-12345'])
    end

    it 'handles nil' do
      expect(described_class.send(:parse_refs, nil)).to be_nil
    end

    it 'handles empty string' do
      expect(described_class.send(:parse_refs, '')).to be_nil
    end

    it 'filters empty elements' do
      refs = 'CVE-2017-0144,,,MS17-010'
      result = described_class.send(:parse_refs, refs)

      expect(result).to eq(['CVE-2017-0144', 'MS17-010'])
    end
  end
end
