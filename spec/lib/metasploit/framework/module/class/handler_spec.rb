require 'spec_helper'

require 'msf/core/handler/bind_tcp'

describe Metasploit::Framework::Module::Class::Handler do
  subject(:base_class) do
    described_class = self.described_class

    Class.new do
      extend described_class
    end
  end

  context '#ancestor_handler_module' do
    subject(:ancestor_handler_module) do
      base_class.ancestor_handler_module
    end

    context 'with Metasploit::Framework::Module::Ancestor::Handler Class#ancestors' do
      let(:handled_ancestor) do
        handler_module = self.handler_module

        Module.new do
          extend Metasploit::Framework::Module::Ancestor::Handler

          handler module_name: handler_module.name
        end
      end

      let(:handler_module) do
        Msf::Handler::BindTcp
      end

      before(:each) do
        base_class.send(:include, handled_ancestor)
      end

      it "should use ancestor's #handler_module" do
        ancestor_handler_module.should == handler_module
      end
    end

    context 'without Metasploit::Framework::Module::Ancestor::Handler Class#ancestors' do
      it { should be_nil }
    end
  end
end