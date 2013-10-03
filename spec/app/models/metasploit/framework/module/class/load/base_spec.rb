require 'spec_helper'

describe Metasploit::Framework::Module::Class::Load::Base do
  include_context 'database seeds'

  subject(:module_class_load) do
    with_established_connection {
      FactoryGirl.build(
          :metasploit_framework_module_class_load_base,
          cache: cache,
          module_class: module_class
      )
    }
  end

  let(:cache) do
    FactoryGirl.create(:metasploit_framework_module_cache)
  end

  let(:module_class) do
    FactoryGirl.create(:mdm_module_class)
  end

  context '#metasploit_class' do
    subject(:metasploit_class) do
      with_established_connection {
        module_class_load.metasploit_class
      }
    end

    context 'with valid?(:loading)' do
      let(:parent_constant) do
        double('Parent Constant')
      end

      let(:relative_constant_name) do
        'RelativeConstantName'
      end

      before(:each) do
        module_class_load.should_receive(:relative_constant_name).once.and_return(relative_constant_name)
        described_class.should_receive(:parent_constant).once.and_return(parent_constant)
      end

      context 'with NameError' do
        before(:each) do
          parent_constant.should_receive(:const_get).with(
              relative_constant_name,
              false
          ).once.and_raise(NameError)
        end

        it 'should write each Metasploit::Framework::Module::Ancestor::Load to the #cache' do
          cache.should_receive(:write_module_ancestor_load) { |module_ancestor_load|
            module_ancestor_load.module_ancestor.should be_in module_class.ancestors

            # return false so metasploit_class exits earlier thinking the cache write failed.
            false
          }.exactly(module_class.ancestors.length).times

          metasploit_class
        end

        context 'cache written' do
          before(:each) do
            cache.should_receive(:write_module_ancestor_load).exactly(
                module_class.ancestors.length
            ).times.and_return(
                written
            )
          end

          context 'with false' do
            let(:written) do
              false
            end

            it { should be_nil }
          end

          context 'with true' do
            let(:written) do
              true
            end

            before(:each) do
              module_class_load.should_receive(:relative_constant_name).once.and_return(relative_constant_name)
              described_class.should_receive(:parent_constant).once.and_return(parent_constant)
            end

            it 'should look up child constant again' do
              parent_constant.should_receive(:const_get).with(
                  relative_constant_name,
                  false
              ).once
              module_class_load.stub(:metasploit_class_from_child_constant)

              metasploit_class
            end

            context 'with NameError' do
              before(:each) do
                parent_constant.should_receive(:const_get).with(
                    relative_constant_name,
                    false
                ).once.and_raise(NameError)
              end

              it { should be_nil }
            end

            context 'without NameError' do
              let(:child_constant) do
                double('Child Constant')
              end

              before(:each) do
                parent_constant.should_receive(:const_get).with(
                    relative_constant_name,
                    false
                ).once.and_return(child_constant)
              end

              it 'should return metasploit_class_from_child_constant' do
                expected_metasploit_class = double('metasploit class')
                module_class_load.should_receive(:metasploit_class_from_child_constant).with(
                    child_constant
                ).and_return(
                    expected_metasploit_class
                )

                metasploit_class.should == expected_metasploit_class
              end
            end
          end
        end
      end

      context 'without NameError' do
        let(:child_constant) do
          double('Child Constant')
        end

        before(:each) do
          parent_constant.should_receive(:const_get).with(
              relative_constant_name,
              false
          ).once.and_return(child_constant)
        end

        it 'should return metasploit_class_from_child_constant' do
          expected_metasploit_class = double('metasploit class')
          module_class_load.should_receive(:metasploit_class_from_child_constant).with(
              child_constant
          ).and_return(
              expected_metasploit_class
          )

          metasploit_class.should == expected_metasploit_class
        end
      end
    end

    context 'without valid?(:loading)' do
      before(:each) do
        module_class_load.stub(:valid?).with(:loading).and_return(false)
      end

      it { should be_nil }
    end
  end
end