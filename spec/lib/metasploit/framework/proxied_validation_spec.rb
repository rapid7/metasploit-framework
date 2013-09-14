require 'spec_helper'

describe Metasploit::Framework::ProxiedValidation do
  it_should_behave_like 'Metasploit::Framework::ProxiedValidation' do
    let(:target) do
      Module.new.tap { |target|
        target.extend described_class

        def target.validation_proxy_class
          Metasploit::Framework::ValidationProxy
        end
      }
    end
  end
end