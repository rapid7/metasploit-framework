require 'stringio'

RSpec.shared_context 'Msf::StringIO' do
  let(:msf_io) do
    StringIO.new('', 'w+b')
  end

  before(:each) do
    def msf_io.get_once
      read
    end

    def msf_io.has_read_data?(_timeout)
      false
    end

    def msf_io.put(_data)
      seek(0)
      write(_data)
      seek(0)
    end
  end
end
