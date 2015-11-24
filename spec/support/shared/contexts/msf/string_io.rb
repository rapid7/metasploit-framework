require 'stringio'

RSpec.shared_context 'Msf::StringIO' do

  #
  # lets
  #

  let(:msf_io) do
    StringIO.new('', 'w+b')
  end

  #
  # Callbacks
  #

  before(:each) do
    def msf_io.set_msf_data(data)
      class << self
        attr_accessor :msf_data
      end

      self.msf_data = data
    end

    def msf_io.get_once
      read
    end

    def msf_io.has_read_data?(_timeout)
      false
    end

    def msf_io.put(_data)
      seek(0)
      if instance_variables.include?(:msf_data)
        write(msf_data)
      else
        write(msf_data)
      end
      seek(0)
    end
  end
end
