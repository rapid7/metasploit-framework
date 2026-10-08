require 'rspec'
require 'metasploit/framework'

RSpec.describe 'auxiliary/server/dhclient_bash_env' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'server/dhclient_bash_env'
    )
  end

  describe '#dhcp_vars' do
    context 'with the default SHELLSHOCK_DHCP_VARS value' do
      it 'returns all three variable names' do
        expect(mod.dhcp_vars).to eq(%w[domainname hostname url])
      end
    end

    context 'with a subset of valid var names' do
      it 'returns only the specified names' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'domainname,url'
        expect(mod.dhcp_vars).to eq(%w[domainname url])
      end
    end

    context 'with a single valid var name' do
      it 'returns a one-element array' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'hostname'
        expect(mod.dhcp_vars).to eq(%w[hostname])
      end
    end

    context 'with leading and trailing whitespace around entries' do
      it 'strips whitespace from each name' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = ' domainname , url '
        expect(mod.dhcp_vars).to eq(%w[domainname url])
      end
    end

    context 'with an invalid var name' do
      it 'raises with a bad-config message naming the offending var' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'domainname,evil'
        expect { mod.dhcp_vars }.to raise_error(Msf::Auxiliary::Failed, /bad-config.*evil/)
      end
    end

    context 'with multiple invalid var names' do
      it 'lists all invalid names in the error message' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'bad1,hostname,bad2'
        expect { mod.dhcp_vars }.to raise_error(Msf::Auxiliary::Failed, /bad1.*bad2|bad2.*bad1/)
      end
    end
  end

  describe '#build_dhcp_vars' do
    let(:payload_value) { '() { :;};id' }

    context 'with the default SHELLSHOCK_DHCP_VARS (all three)' do
      it 'sets DOMAINNAME, HOSTNAME, and URL to the payload value' do
        result = mod.build_dhcp_vars(payload_value)
        expect(result).to eq(
          'DOMAINNAME' => payload_value,
          'HOSTNAME' => payload_value,
          'URL' => payload_value
        )
      end
    end

    context 'with only domainname' do
      it 'sets only DOMAINNAME' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'domainname'
        result = mod.build_dhcp_vars(payload_value)
        expect(result).to eq('DOMAINNAME' => payload_value)
      end
    end

    context 'with only hostname' do
      it 'sets only HOSTNAME' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'hostname'
        result = mod.build_dhcp_vars(payload_value)
        expect(result).to eq('HOSTNAME' => payload_value)
      end
    end

    context 'with only url' do
      it 'sets only URL' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'url'
        result = mod.build_dhcp_vars(payload_value)
        expect(result).to eq('URL' => payload_value)
      end
    end

    context 'with hostname and url' do
      it 'does not include DOMAINNAME' do
        mod.datastore['SHELLSHOCK_DHCP_VARS'] = 'hostname,url'
        result = mod.build_dhcp_vars(payload_value)
        expect(result.keys).not_to include('DOMAINNAME')
        expect(result).to include('HOSTNAME' => payload_value, 'URL' => payload_value)
      end
    end
  end
end
