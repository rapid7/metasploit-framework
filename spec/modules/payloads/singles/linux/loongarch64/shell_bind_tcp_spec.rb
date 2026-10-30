require 'spec_helper'

RSpec.describe 'modules/payloads/singles/linux/loongarch64/shell_bind_tcp' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'linux/loongarch64/shell_bind_tcp',
      ancestor_reference_names: ['singles/linux/loongarch64/shell_bind_tcp']
    )
  end

  before do
    subject.datastore.merge!('LPORT' => 4444, 'VERBOSE' => true)
  end

  describe '#generate' do
    it 'matches the cached size' do
      expect(subject.generate.bytesize).to eq(subject.class::CachedSize)
    end

    it 'encodes the port in network byte order' do
      expect(subject.generate[198, 2]).to eq([4444].pack('n'))
    end

    it 'regenerates the listening port when the datastore changes' do
      subject.datastore['LPORT'] = 65_535
      expect(subject.generate[198, 2]).to eq([65_535].pack('n'))
    end

    it 'uses INADDR_ANY' do
      expect(subject.generate[200, 4]).to eq("\x00" * 4)
    end
  end
end
