require 'stringio'

RSpec.shared_context 'Msf::StringIO' do

  #
  # lets
  #

  let(:msf_io) do
    s = StringIO.new('', 'w+b')
    class << s
      attr_accessor :msf_data
    end

    s.msf_data = ''

    s
  end

  #
  # Callbacks
  #

  before(:example) do
    def msf_io.get_once
      read
    end

    def msf_io.has_read_data?(_timeout)
      !eof?
    end

    def msf_io.put(_data)
      seek(0)

      if msf_data.nil? || msf_data.empty?
        length = write(_data)
      else
        length = write(msf_data)
      end

      seek(0)

      length
    end
  end
end
