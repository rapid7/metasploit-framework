require 'spec_helper'

describe Metasploit::Framework::Module::Class::MetasploitClass do
  include_context 'database seeds'

  subject(:base_class) do
    described_class = self.described_class
    rank = self.rank

    Class.new do
      extend described_class

      define_singleton_method(:rank_name) do
        rank.name
      end

      define_singleton_method(:rank_number) do
        rank.number
      end
    end
  end

  let(:rank) do
    with_established_connection {
      FactoryGirl.generate :mdm_module_rank
    }
  end

  context 'resurrecting attributes' do
    context '#module_class' do
      subject(:module_class) do
        with_established_connection {
          base_class.module_class
        }
      end

      let(:expected_module_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: module_type,
            payload_type: payload_type
        )
      end

      before(:each) do
        with_established_connection do
          expected_module_class.ancestors.each_with_index do |module_ancestor, i|
            metasploit_module = Module.new do
              extend Metasploit::Framework::Module::Ancestor::MetasploitModule
            end

            # double parent so an outer namespace module does not need to be declared and named
            parent = double(
                "Parent #{i}",
                real_path_sha1_hex_digest: module_ancestor.real_path_sha1_hex_digest
            )
            metasploit_module.stub(parent: parent)

            base_class.send(:include, metasploit_module)
          end
        end
      end

      context 'module_type' do
        context 'with payload' do
          let(:module_type) do
            'payload'
          end

          context 'payload_type' do
            context 'with single' do
              let(:payload_type) do
                'single'
              end

              it 'should be pre-existing Mdm::Module:Class' do
                module_class.should == expected_module_class
              end
            end

            context 'with staged' do
              let(:payload_type) do
                'staged'
              end

              it 'should be pre-existing Mdm::Module:Class' do
                module_class.should == expected_module_class
              end
            end
          end
        end

        context 'without payload' do
          let(:module_type) do
            FactoryGirl.generate :metasploit_model_non_payload_module_type
          end

          let(:payload_type) do
            nil
          end

          it 'should be pre-existing Mdm::Module:Class' do
            module_class.should == expected_module_class
          end
        end
      end
    end
  end

  context '#cache_module_class' do
    subject(:cache_module_class) do
      with_established_connection {
        base_class.cache_module_class(module_class)
      }
    end

    let(:module_class) do
      with_established_connection {
        FactoryGirl.build(:mdm_module_class)
      }
    end

    before(:each) do
      # blank the rank here to ensure cache_rank works, but don't blank on factory to ensure its still in the contents.
      module_class.rank = nil
    end

    context 'with error in cache_rank' do
      before(:each) do
        base_class.stub(:rank_name).and_raise(NoMethodError)
      end

      it 'should not raise error' do
        expect {
          cache_module_class
        }.to_not raise_error
      end

      it 'should not create Mdm::Module::Class' do
        expect {
          cache_module_class
        }.to_not change {
          with_established_connection {
            Mdm::Module::Class.count
          }
        }
      end
    end

    context 'without error in cache_rank' do
      it 'should call #cache_rank' do
        base_class.should_receive(:cache_rank).with(module_class).and_call_original

        cache_module_class
      end

      context 'with unique record' do
        it 'should create Mdm::Module::Class' do
          expect {
            cache_module_class
          }.to change {
            with_established_connection {
              Mdm::Module::Class.count
            }
          }.by(1)
        end

        context 'Mdm::Module::Class' do
          subject do
            module_class
          end

          before(:each) do
            cache_module_class
          end

          it 'should have rank with same name as #rank_name' do
            module_class.rank.name.should == base_class.rank_name
          end
        end
      end

      context 'without unique record' do
        before(:each) do
          with_established_connection {
            base_class.cache_module_class(module_class)
          }

          # this would actually occur if two staged payloads had the same name.
          module_class.instance_variable_set(:@new_record, true)
          module_class.id = nil
        end

        specify {
          expect {
            cache_module_class
          }.to_not raise_error(ActiveRecord::RecordNotUnique)
        }
      end
    end
  end

  context '#cache_rank' do
    subject(:cache_rank) do
      with_established_connection {
        base_class.cache_rank(module_class)
      }
    end

    let(:module_class) do
      with_established_connection {
        FactoryGirl.build(
            :mdm_module_class,
            rank: nil
        )
      }
    end

    context 'with error in rank_name' do
      before(:each) do
        base_class.stub(:rank_name).and_raise(NoMethodError)
      end

      it 'should not raise exception' do
        expect {
          cache_rank
        }.to_not raise_error
      end
    end

    context 'without error in rank_name' do
      it 'should set module_class.rank' do
        expect {
          cache_rank
        }.to change {
          module_class.rank
        }.to(rank)
      end
    end
  end

  context '#each_module_ancestor' do
    context 'with block' do
      def each_module_ancestor(&block)
        with_established_connection {
          base_class.each_module_ancestor(&block)
        }
      end

      context 'with module ancestors' do
        let(:module_ancestors) do
          # as a fixed array to ensure fixed order
          module_class.ancestors.to_a
        end

        # staged payloads are the only module classes with two module ancestors, so they have to be the test case
        # to ensure more than one module ancestor is yielded
        let(:module_class) do
          with_established_connection {
            FactoryGirl.create(
                :mdm_module_class,
                module_type: 'payload',
                payload_type: 'staged'
            )
          }
        end

        before(:each) do
          module_ancestors.each_with_index do |module_ancestor, i|
            metasploit_module = Module.new do
              extend Metasploit::Framework::Module::Ancestor::MetasploitModule
            end

            # double parent so an outer namespace module does not need to be declared and named
            parent = double(
                "Parent #{i}",
                real_path_sha1_hex_digest: module_ancestor.real_path_sha1_hex_digest
            )
            metasploit_module.stub(parent: parent)

            base_class.send(:include, metasploit_module)
          end
        end

        it 'should return module_ancestor from each metasploit_module Class#ancestor' do
          expect { |block|
            each_module_ancestor(&block)
          }.to yield_successive_args(
                   # reverse order because Class#ancestors are reverse of include order
                   *module_ancestors.reverse
               )
        end
      end

      context 'without module ancestors' do
        specify {
          expect { |block|
            each_module_ancestor(&block)
          }.not_to yield_control
        }
      end
    end

    context 'without block' do
      subject(:each_module_ancestor) do
        base_class.each_module_ancestor
      end

      it { should be_an Enumerator }
    end
  end
end