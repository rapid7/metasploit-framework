require 'spec_helper'

RSpec.describe 'post/windows/gather/enum_applications' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'post',
      reference_name: 'windows/gather/enum_applications'
    )
  end

  describe '#app_list' do
    before do
      allow(mod).to receive(:registry_enumkeys) do |key|
        ['Shared App'] if key.start_with?('HKLM')
      end
      allow(mod).to receive(:registry_getvaldata) do |_key, value|
        value == 'DisplayName' ? 'Shared App' : '1.2.3'
      end
      allow(mod.framework.threads).to receive(:spawn) do |_name, _critical, key, &block|
        block.call(key) if key
        double(join: nil)
      end
      allow(mod).to receive(:session).and_return(double)
      allow(mod).to receive(:store_loot).and_return('/tmp/applications.txt')
      allow(mod).to receive(:print_good)
    end

    it 'prints each application and version once across overlapping registry views' do
      expect(mod).to receive(:print_line) do |output|
        expect(output.scan('Shared App').length).to eq(1)
        expect(output.scan('1.2.3').length).to eq(1)
      end

      mod.app_list
    end

    it 'keeps distinct versions of the same application' do
      allow(mod).to receive(:registry_enumkeys).and_return(['Shared App'])
      allow(mod).to receive(:registry_getvaldata) do |key, value|
        if value == 'DisplayName'
          'Shared App'
        elsif key.start_with?('HKCU')
          '2.0.0'
        else
          '1.2.3'
        end
      end

      expect(mod).to receive(:print_line) do |output|
        expect(output.scan('Shared App').length).to eq(2)
        expect(output.scan('1.2.3').length).to eq(1)
        expect(output.scan('2.0.0').length).to eq(1)
      end

      mod.app_list
    end
  end
end
