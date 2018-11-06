RSpec.describe Metasploit::Model::Association do
  subject(:base_class) do
    described_class = self.described_class

    Class.new do
      include described_class
    end
  end

  context 'association' do
    subject(:reflection) do
      base_class.association name, :class_name => class_name
    end

    let(:class_name) do
      ''
    end

    let(:name) do
      ''
    end

    context 'with blank name' do
      it 'should raise Metasploit::Model::Invalid' do
        expect {
          reflection
        }.to raise_error(Metasploit::Model::Invalid)
      end
    end

    context 'without blank name' do
      let(:name) do
        'associated_things'
      end

      context 'with blank :class_name' do
        it 'should raise Metasploit::Model::Invalid' do
          expect {
            reflection
          }.to raise_error(Metasploit::Model::Invalid)
        end
      end

      context 'without blank :class_name' do
        let(:class_name) do
          'AssociatedThing'
        end

        context 'model' do
          subject(:model) do
            reflection.model
          end

          it 'should be class on which association was called' do
            expect(model).to eq(base_class)
          end
        end

        context 'name' do
          subject(:reflection_name) do
            reflection.name
          end

          it 'should be name passed to association as a Symbol' do
            expect(reflection_name).to eq(name.to_sym)
          end
        end

        context 'class_name' do
          subject(:reflection_class_name) do
            reflection.class_name
          end

          it 'should be :class_name passed to association' do
            expect(reflection_class_name).to eq(class_name)
          end
        end
      end
    end
  end

  context 'association_by_name' do
    subject(:association_by_name) do
      base_class.association_by_name
    end

    it 'should default to empty Hash' do
      expect(association_by_name).to eq({})
    end
  end

  context 'reflect_on_association' do
    subject(:reflection) do
      base_class.reflect_on_association(reflected_name)
    end

    let(:class_name) do
      'AssociatedThing'
    end

    let(:name) do
      :associated_things
    end

    before(:example) do
      base_class.association name, :class_name => class_name
    end

    context 'with named association' do
      let(:reflected_name) do
        name
      end

      context 'class_name' do
        subject(:reflection_class_name) do
          reflection.class_name
        end

        it 'should be class_name passed to association' do
          expect(reflection_class_name).to eq(class_name)
        end
      end

      context 'name' do
        subject(:reflection_name) do
          reflection.name
        end

        it 'should have the reflected name' do
          expect(reflection.name).to eq(reflected_name)
        end
      end
    end

    context 'without named association' do
      let(:reflected_name) do
        :unassociated_things
      end

      it { is_expected.to be_nil }
    end
  end
end