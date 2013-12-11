require 'spec_helper'

describe Msf::Simple::Framework do
  context 'CONSTANTS' do
    context 'ModuleSimplifiers' do
      subject(:module_simplifiers) do
        described_class::ModuleSimplifiers
      end

      it 'should simplify Metasploit::Model::Module::Type::AUX with Msf::Simple::Auxiliary' do
        module_simplifiers[Metasploit::Model::Module::Type::AUX].should == Msf::Simple::Auxiliary
      end

      it 'should simplify Metasploit::Model::Module::Type::ENCODER with Msf::Simple::Encoder' do
        module_simplifiers[Metasploit::Model::Module::Type::ENCODER].should == Msf::Simple::Encoder
      end

      it 'should simplify Metasploit::Model::Module::Type::EXPLOIT with Msf::Simple::Exploit' do
        module_simplifiers[Metasploit::Model::Module::Type::EXPLOIT].should == Msf::Simple::Exploit
      end

      it 'should simplify Metasploit::Model::Module::Type::NOP with Msf::Simple::Nop' do
        module_simplifiers[Metasploit::Model::Module::Type::NOP].should == Msf::Simple::Nop
      end

      it 'should simplify Metasploit::Model::Module::Type::PAYLOAD with Msf::Simple::Payload' do
        module_simplifiers[Metasploit::Model::Module::Type::PAYLOAD].should == Msf::Simple::Payload
      end

      it 'should simplify Metasploit::Model::Module::Type::POST with Msf::Simple::Post' do
        module_simplifiers[Metasploit::Model::Module::Type::POST].should == Msf::Simple::Post
      end
    end
  end

  it_should_behave_like 'Msf::Simple::Framework::ModulePaths' do
    include_context 'Msf::Simple::Framework'

    subject do
      framework
    end
  end

  context 'create' do
    context 'with options' do
      subject(:create) do
        described_class.create(options)
      end

      let(:options) do
        {}
      end

      context "['DisableDatabase']" do
        context 'with value' do
          let(:options) do
            {
                'DisableDatabase' => disable_database
            }
          end

          context 'with false' do
            let(:disable_database) do
              false
            end

            it 'should pass database_disabled: false to Msf::Framework.new' do
              framework = double("Msf::Framework").as_null_object
              Msf::Framework.should_receive(:new).with(
                  hash_including(
                      database_disabled: false
                  )
              ).and_call_original
              described_class.stub(:simplify)

              create
            end
          end

          context 'with nil' do
            let(:disable_database) do
              nil
            end

            it 'should pass database_disabled: false to Msf::Framework.new' do
              Msf::Framework.should_receive(:new).with(
                  hash_including(
                      database_disabled: false
                  )
              ).and_call_original
              described_class.stub(:simplify)

              create
            end
          end

          context 'with true' do
            let(:disable_database) do
              true
            end

            it 'should pass database_disabled: true to Msf::Framework.new' do
              Msf::Framework.should_receive(:new).with(
                  hash_including(
                      database_disabled: true
                  )
              ).and_call_original
              described_class.stub(:simplify)

              create
            end
          end
        end

        context 'without value' do
          it 'should pass database_disabled: false to Msf::Framework.new' do
            Msf::Framework.should_receive(:new).with(
                hash_including(
                    database_disabled: false
                )
            ).and_call_original
            described_class.stub(:simplify)

            create
          end
        end
      end

      context '[:module_types]' do
        let(:options) do
          {
              module_types: module_types
          }
        end

        context 'with valid module types' do
          include_context 'database cleaner'

          subject(:module_types) do
            # 1 .. length instead of 0 .. length since there needs to be at least one module_type
            number = rand(Metasploit::Model::Module::Type::ALL.length - 1) + 1
            # random module_types
            Metasploit::Model::Module::Type::ALL.sample(number)
          end

          it 'should pass module_types option to Msf::Framework.new' do
            Msf::Framework.should_receive(:new).with(
                hash_including(
                    module_types: module_types
                )
            ).and_call_original

            create
          end

          it 'should simplify Msf::Framework using options' do
            described_class.should_receive(:simplify).with(an_instance_of(Msf::Framework), options)

            create
          end
        end

        context 'without valid module types' do
          let(:module_types) do
            ['not_a_module_type']
          end

          it 'should raise Metasploit::Model::Invalid' do
            expect {
              create
            }.to raise_error(Metasploit::Model::Invalid)
          end
        end
      end
    end

    context 'without options' do
      include_context 'database cleaner'

      subject(:create) do
        described_class.create
      end

      after(:each) do
        # explicitly kill threads so that they don't exhaust connection pool
        thread_manager = create.threads
        threads = thread_manager.list

        threads.each do |thread|
          thread.kill
        end
      end

      it 'should be_a Msf::Framework' do
        create.should be_a  Msf::Framework
      end

      it 'should be_a Msf::Simple::Framework' do
        create.should be_a Msf::Simple::Framework
      end
    end
  end
end