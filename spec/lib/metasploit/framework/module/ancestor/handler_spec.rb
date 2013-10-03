require 'spec_helper'

require 'msf/core/handler/bind_tcp'

describe Metasploit::Framework::Module::Ancestor::Handler do
  subject(:base_module) do
    described_class = self.described_class

    Module.new do
      extend described_class
    end
  end

  context '#handler' do
    subject(:handler) do
      base_module.handler(options)
    end

    let(:options) do
      {}
    end

    context 'without :module_name' do
      specify {
        expect {
          handler
        }.to raise_error KeyError
      }
    end

    context 'after calling' do
      before(:each) do
        handler
      end

      context 'with :module_name' do
        let(:options) do
          {
              module_name: module_name
          }
        end

        let(:module_name) do
          named_module.name
        end

        let(:named_module) do
          Msf::Handler::BindTcp
        end

        context '#handler_module' do
          subject(:handler_module) do
            base_module.handler_module
          end

          it 'should be the Module with Module#name equal to :module_name' do
            handler_module.should == named_module
          end
        end

        context '#handler_module_name' do
          subject(:handler_module_name) do
            base_module.handler_module_name
          end

          it 'should be :module_name' do
            handler_module_name.should == module_name
          end
        end

        context ':type_alias' do
          context '#handler_type_alias' do
            subject(:handler_type_alias) do
              base_module.handler_type_alias
            end

            context 'without option' do
              it 'should use #handler_module handler_type' do
                handler_type_alias.should == named_module.handler_type
              end
            end

            context 'with option' do
              let(:options) do
                super().merge(
                    type_alias: type_alias
                )
              end

              let(:type_alias) do
                'another_type'
              end

              it 'should use :type_alias' do
                handler_type_alias.should == type_alias
              end
            end
          end
        end
      end
    end
  end

  context '#handler_module' do
    subject(:handler_module) do
      base_module.handler_module
    end

    it 'should default to Msf::Handler::None' do
      handler_module.should == Msf::Handler::None
    end
  end

  context '#handler_module_name' do
    subject(:handler_module_name) do
      base_module.handler_module_name
    end

    it "should default to 'Msf::Handler::None'" do
      handler_module_name.should == 'Msf::Handler::None'
    end
  end

  context '#handler_type_alias' do
    subject(:handler_type_alias) do
      base_module.handler_type_alias
    end

    it "should default to 'none'" do
      handler_type_alias.should == 'none'
    end
  end
end