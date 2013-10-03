require 'spec_helper'

describe Metasploit::Framework::ResurrectingAttribute do
  subject(:base_class) do
    described_class = self.described_class

    Class.new do
      extend described_class
    end
  end

  context '#resurrecting_attr_accessor' do
    subject(:resurrecting_attr_accessor) do
      base_class.resurrecting_attr_accessor attribute_name, &block
    end

    let(:attribute_name) do
      :phoenix
    end

    let(:block) do
      ->() { deferred }
    end

    context 'after declaring' do
      before(:each) do
        resurrecting_attr_accessor
      end

      context 'instance' do
        subject(:base_instance) do
          base_class.new
        end

        let(:instance_variable_name) do
          "@#{attribute_name}".to_sym
        end

        let(:read) do
          base_instance.send(attribute_name)
        end

        let(:writer_name) do
          "#{attribute_name}="
        end

        context 'read' do
          subject do
            read
          end

          let(:reader_name) do
            attribute_name
          end

          before(:each) do
            @deferred = 'Deferred'
            base_instance.stub(deferred: @deferred)
          end

          it 'should respond to <attribute_name>' do
            base_instance.should respond_to attribute_name
          end

          context 'without value' do
            it 'should instance_exec block passed to resurrecting_attr_accessor' do
              base_instance.should_receive(:instance_exec) { |&actual_block|
                actual_block.should == block
              }.and_call_original

              read
            end

            it 'should set value equal to return from block passed to resurrecting_attr_accessor' do
              base_instance.should_receive(writer_name).with(@deferred)

              read
            end

            it 'should return value from block' do
              read.should == @deferred
            end
          end

          context 'with value' do
            let(:value) do
              'written value'
            end

            before(:each) do
              base_instance.send(writer_name, value)
            end

            it 'should get strong reference using WeakRef#__getobj__' do
              weak_reference = base_instance.instance_variable_get instance_variable_name
              weak_reference.should_receive(:__getobj__)

              read
            end

            context 'with WeakRef::RefError' do
              it 'should get value from block again' do
                base_instance.send(writer_name, Object.new)
                # ensure written value is collected to trigger WeakRef::RefError
                # using double GC as one wasn't enough and weakref's test double garbase collect, so assume it's enough.
                GC.start
                GC.start

                base_instance.should_receive(:instance_exec) { |&actual_block|
                  actual_block.should == block
                }.and_call_original

                read
              end
            end

            context 'without WeakRef::RefError' do
              it 'should no call block again' do
                strong_reference = Object.new
                base_instance.send(writer_name, strong_reference)

                # using double GC as one wasn't enough and weakref's test double garbase collect, so assume it's enough.
                GC.start
                GC.start

                base_instance.should_not_receive(:instance_exec) { |&actual_block|
                  actual_block.should == block
                }.and_call_original

                read
              end
            end
          end
        end

        context 'write' do
          subject(:write) do
            base_instance.send(writer_name, value)
          end

          let(:value) do
            Object.new
          end

          it 'should respond to <attribute_name>=' do
            base_instance.should respond_to writer_name
          end

          it 'should create a WeakRef to value' do
            write

            weak_reference = base_instance.instance_variable_get(instance_variable_name)
            weak_reference.should be_a WeakRef
            weak_reference.__getobj__.should == value
          end

          context 'with nil' do
            let(:value) do
              nil
            end

            specify {
              expect {
                write
              }.to_not raise_error
            }
          end

          context 'without nil' do
            let(:value) do
              Object.new
            end

            it 'should be readable' do
              write
              read.should == value
            end

            it 'should return strong reference and not WeakRef' do
              write.should_not be_a WeakRef
              write.should equal(value)
            end
          end
        end
      end
    end
  end
end