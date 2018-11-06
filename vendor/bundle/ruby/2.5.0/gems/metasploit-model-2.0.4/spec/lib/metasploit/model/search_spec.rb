RSpec.describe Metasploit::Model::Search do
  subject(:base_instance) do
    base_class.new
  end

  let(:base_class) do
    Class.new
  end

  before(:example) do
    # class needs to be named or search_i18n_scope will error
    stub_const('Searched', base_class)

    base_class.send(:include, described_class)
  end

  it { is_expected.to be_a Metasploit::Model::Search::Association }
  it { is_expected.to be_a Metasploit::Model::Search::Attribute }
  it { is_expected.to be_a Metasploit::Model::Search::With }

  context 'search_operator_by_name' do
    subject(:search_operator_by_name) do
      base_class.search_operator_by_name
    end

    context 'with search attribute' do
      let(:attribute) do
        :searched_attribute
      end

      before(:example) do
        base_class.search_attribute attribute, :type => :string
      end

      context 'operator' do
        subject(:operator) do
          search_operator_by_name[attribute]
        end

        context 'name' do
          subject(:name) do
            operator.name
          end

          it 'should be same as the attribute' do
            expect(name).to eq(attribute)
          end
        end
      end
    end

    context 'with search association' do
      let(:associated_attribute) do
        :association_name
      end

      let(:association) do
        :associated_things
      end

      let(:association_class) do
        Class.new
      end

      let(:class_name) do
        'AssociatedThing'
      end

      before(:example) do
        base_class.search_association association
        base_class.send(:include, Metasploit::Model::Association)

        stub_const(class_name, association_class)

        # Include after stub so search_i18n_scope can use Class#name without error
        association_class.send(:include, Metasploit::Model::Search)
        association_class.search_attribute associated_attribute, :type => :string

        base_class.association association, :class_name => class_name
      end

      context 'operator' do
        subject(:operator) do
          search_operator_by_name[expected_name]
        end

        let(:expected_name) do
          "#{association}.#{associated_attribute}".to_sym
        end

        it { is_expected.to be_a Metasploit::Model::Search::Operator::Association }

        context 'association' do
          subject(:operator_association) do
            operator.association
          end

          it 'should be the registered association' do
            expect(operator_association).to eq(association)
          end
        end

        context 'source_operator' do
          subject(:source_operator) do
            operator.source_operator
          end

          let(:direct_attribute_operator) do
            association_class.search_operator_by_name.values.first
          end

          it 'should be operator from associated class' do
            expect(source_operator).to eq(direct_attribute_operator)
          end
        end

        context 'klass' do
          subject(:klass) do
            operator.klass
          end

          it 'should be class that called search_operator_by_name' do
            expect(klass).to eq(base_class)
          end
        end
      end
    end

    context 'with search with' do
      let(:name) do
        :searched_with
      end

      let(:operator) do
        double(
            'Operator',
            :name => name,
            :valid! => nil
        )
      end

      let(:operator_class) do
        double('Operator Class', :new => operator)
      end

      before(:example) do
        base_class.search_with operator_class
      end

      context 'operator' do
        subject(:named_operator) do
          search_operator_by_name[name]
        end

        it 'should be in search_operator_by_name' do
          expect(named_operator).to eq(operator)
        end
      end
    end

    context 'without search attribute' do
      context 'without search association' do
        context 'without search with' do
          it { is_expected.to be_empty }
        end
      end
    end
  end
end