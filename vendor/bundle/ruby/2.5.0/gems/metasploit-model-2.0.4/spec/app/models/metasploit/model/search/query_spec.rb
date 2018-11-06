RSpec.describe Metasploit::Model::Search::Query, type: :model do
  context 'validations' do
    it { is_expected.to validate_presence_of :klass }

    context 'operations' do
      let(:errors) do
        query.errors[:operations]
      end

      let(:klass) do
        Class.new
      end

      let(:query) do
        described_class.new(
            :formatted => formatted,
            :klass => klass
        )
      end

      before(:example) do
        stub_const('Queried', klass)

        # include after stubbing constant so that Class#name can be used for search_i18n_scope
        klass.send(:include, Metasploit::Model::Search)
      end

      context 'length' do
        let(:error) do
          I18n.translate(
              'metasploit.model.errors.models.metasploit/model/search/query.attributes.operations.too_short',
              :count => 1
          )
        end

        before(:example) do
          query.valid?
        end

        context 'with empty' do
          let(:formatted) do
            ''
          end

          it 'should have no operations' do
            expect(query.operations.length).to eq(0)
          end

          it 'should record error on operations' do
            expect(errors).to include(error)
          end
        end

        context 'without empty' do
          let(:formatted) do
            'formatted_operator:formatted_value'
          end

          it 'should not record error on operations' do
            expect(errors).not_to include(error)
          end
        end
      end

      context 'valid' do
        let(:error) do
          'is invalid'
        end

        let(:query) do
          described_class.new
        end

        before(:example) do
          operation = double('Invalid Operation', :valid? => valid)
          allow(query).to receive(:operations).and_return([operation])
        end

        context 'with invalid operation' do
          let(:valid) do
            false
          end

          it 'should record error on operations' do
            expect(errors).not_to include(error)
          end
        end

        context 'without invalid operation' do
          let(:valid) do
            true
          end

          it 'should not record error on options' do
            expect(errors).not_to include(error)
          end
        end
      end
    end
  end

  context 'formatted_operations' do
    subject(:formatted_operations) do
      described_class.formatted_operations(formatted_query)
    end

    context 'with quoted value' do
      let(:formatted_query) do
        # embedded : in quotes to make sure it's not be being split on words around each :.
        'formatted_operator1:"formatted value:1" formatted_operator2:formatted_value2'
      end

      it 'should parse the correct number of formatted_operations' do
        expect(formatted_operations.length).to eq(2)
      end

      it 'should include operation with space in value' do
        expect(formatted_operations).to include('formatted_operator1:formatted value:1')
      end

      it 'should include operation without space in value' do
        expect(formatted_operations).to include('formatted_operator2:formatted_value2')
      end
    end

    context 'with unquoted value' do
      let(:expected_formatted_operations) do
        [
            'formatted_operator1:formatted_value1',
            'formatted_operator2:formatted_value2'
        ]
      end

      let(:formatted_query) do
        expected_formatted_operations.join(' ')
      end

      it 'should parse correct number of formatted operations' do
        expect(formatted_operations.length).to eq(expected_formatted_operations.length)
      end

      it 'should include all formatted operations' do
        expect(formatted_operations).to match_array(expected_formatted_operations)
      end
    end

    context 'with nil' do
      let(:formatted_operations) do
        nil
      end

      it { be_empty }
    end
  end

  context '#formatted_operations' do
    subject(:formatted_operations) do
      query.formatted_operations
    end

    context 'with :formatted_operations attribute' do
      let(:expected_formatted_operations) do
        double('#formatted_operations')
      end

      let(:query) do
        described_class.new(
            formatted_operations: expected_formatted_operations
        )
      end

      it 'should equal attribute passed to #initialize' do
        expect(formatted_operations).to eq(expected_formatted_operations)
      end
    end

    context 'without :formatted_operations attribute' do
      let(:formatted) do
        "#{formatted_operator}:#{formatted_value}"
      end

      let(:formatted_operator) do
        ''
      end

      let(:formatted_value) do
        ''
      end

      let(:klass) do
        Class.new
      end

      let(:query) do
        described_class.new(
            formatted: formatted,
            klass: klass
        )
      end

      before(:example) do
        stub_const('QueriedClass', klass)

        # include after stubbing const so that search_i18n_scope can use Class#name
        klass.send(:include, Metasploit::Model::Search)
      end

      it 'should parse #formatted with formatted_operations' do
        expect(described_class).to receive(:formatted_operations).with(formatted).and_return([])

        formatted_operations
      end
    end
  end

  context '#operations' do
    subject(:operations) do
      query.operations
    end

    context 'with :operations attribute' do
      let(:expected_operations) do
        double('#operations')
      end

      let(:query) do
        described_class.new(
            operations: expected_operations
        )
      end

      it 'should use attribute passed to #initialize' do
        expect(operations).to eq(expected_operations)
      end
    end

    context 'without :operations attribute' do
      let(:attribute) do
        :searchable
      end

      let(:formatted) do
        "#{formatted_operator}:#{formatted_value}"
      end

      let(:formatted_operator) do
        ''
      end

      let(:formatted_value) do
        ''
      end

      let(:klass) do
        Class.new
      end

      let(:query) do
        described_class.new(
            :formatted => formatted,
            :klass => klass
        )
      end

      before(:example) do
        stub_const('QueriedClass', klass)

        # include after stubbing const so that search_i18n_scope can use Class#name
        klass.send(:include, Metasploit::Model::Search)
      end

      it 'should call #formatted_operations' do
        expect(query).to receive(:formatted_operations).and_return([])

        operations
      end

      context 'with known operator' do
        subject(:operator) do
          operations.first
        end

        let(:formatted_operator) do
          @operator.name
        end

        let(:formatted_value) do
          ''
        end

        before(:example) do
          @operator = klass.search_attribute attribute, :type => type
        end

        context 'with boolean operator' do
          let(:type) do
            :boolean
          end

          it { is_expected.to be_a Metasploit::Model::Search::Operation::Boolean }

          context "with 'true'" do
            let(:formatted_value) do
              'true'
            end

            it { is_expected.to be_valid }
          end

          context "with 'false'" do
            let(:formatted_value) do
              'false'
            end

            it { is_expected.to be_valid }
          end

          context "without 'false' or 'true'" do
            let(:formatted_value) do
              'no'
            end

            it { is_expected.to_not be_valid }
          end
        end

        context 'with date operator' do
          let(:type) do
            :date
          end

          it { is_expected.to be_a Metasploit::Model::Search::Operation::Date }

          context 'with date' do
            let(:formatted_value) do
              Date.today.to_s
            end

            it { is_expected.to be_valid }
          end

          context 'without date' do
            let(:formatted_value) do
              'yesterday'
            end

            it { is_expected.to_not be_valid }
          end
        end

        context 'with integer operator' do
          let(:type) do
            :integer
          end

          it { is_expected.to be_a Metasploit::Model::Search::Operation::Integer }

          context 'with integer' do
            let(:formatted_value) do
              '100'
            end

            it { is_expected.to be_valid }
          end

          context 'with float' do
            let(:formatted_value) do
              '100.5'
            end

            it { is_expected.to be_invalid }
          end

          context 'with integer embedded in text' do
            let(:formatted_value) do
              'a2c'
            end

            it { is_expected.to be_invalid }
          end
        end

        context 'with string operator' do
          let(:type) do
            :string
          end

          it { is_expected.to be_a Metasploit::Model::Search::Operation::String }

          context 'with value' do
            let(:formatted_value) do
              'formatted_value'
            end

            it { is_expected.to be_valid }
          end

          context 'without value' do
            let(:formatted_value) do
              ''
            end

            it { is_expected.to_not be_valid }
          end
        end
      end

      context 'without known operator' do
        subject(:operation) do
          operations.first
        end

        let(:formatted_operator) do
          'unknown_operator'
        end

        let(:formatted_value) do
          'unknown_value'
        end

        it { is_expected.to be_a Metasploit::Model::Search::Operation::Base }

        it { is_expected.to be_invalid }
      end
    end
  end

  context '#operations_by_operator' do
    subject(:operations_by_operator) do
      query.operations_by_operator
    end

    let(:klass) do
      Class.new
    end

    let(:query) do
      described_class.new(
          :formatted => formatted,
          :klass => klass
      )
    end

    before(:example) do
      stub_const('Queried', klass)

      klass.send(:include, Metasploit::Model::Search)

      @operators = [:first, :second].collect { |attribute|
        klass.search_attribute attribute, :type => :string
      }
    end

    context 'with valid' do
      let(:formatted) do
        formatted_operators = []

        @operators.each_with_index do |operator, i|
          2.times.each do |j|
            formatted_operator = "#{operator.name}:formatted_value(#{i},#{j})"
            formatted_operators << formatted_operator
          end
        end

        formatted_operators.join(' ')
      end

      it 'should have correct number of groups' do
        expect(operations_by_operator.length).to eq(@operators.length)
      end

      it 'should have correct value for each operator' do
        @operators.each_with_index do |operator, i|
          expected_formatted_values = 2.times.collect { |j|
            "formatted_value(#{i},#{j})"
          }

          operations = operations_by_operator[operator]
          actual_formatted_values = operations.map(&:value)

          expect(actual_formatted_values).to match_array(expected_formatted_values)
        end
      end

      context 'query' do
        subject do
          query
        end

        it { is_expected.to be_valid }
      end
    end

    context 'without valid' do
      let(:formatted) do
        'unknown_formatted_operator:formatted_value'
      end

      context 'query' do
        subject do
          query
        end

        it { is_expected.to_not be_valid }
      end
    end
  end

  context '#parse_operator' do
    subject(:parse_operator) do
      query.parse_operator(formatted_operator)
    end

    let(:attribute) do
      :searched
    end

    let(:klass) do
      Class.new
    end

    let(:query) do
      described_class.new(
          :klass => klass
      )
    end

    before(:example) do
      stub_const('QueriedClass', klass)

      # include after stubbing const so that search_i18n_scope can use Class#name
      klass.send(:include, Metasploit::Model::Search)
      @operator = klass.search_attribute attribute, :type => :string
    end

    context 'with operator name' do
      let(:formatted_operator) do
        attribute.to_s
      end

      context 'with String' do
        it 'should find operator' do
          expect(parse_operator).to eq(@operator)
        end
      end

      context 'with Symbol' do
        let(:formatted_operator) do
          attribute
        end

        it 'should find operator' do
          expect(parse_operator).to eq(@operator)
        end
      end
    end

    context 'without operator name' do
      let(:formatted_operator) do
        'unknown_operator'
      end

      it { is_expected.to be_a Metasploit::Model::Search::Operator::Null }
    end
  end

  context '#tree' do
    subject(:tree) do
      query.tree
    end

    let(:formatted) do
      'thing_one:1 thing_two:2 thing_one:a thing_two:b'
    end

    let(:klass) do
      Class.new
    end

    let(:query) do
      described_class.new(
          :formatted => formatted,
          :klass => klass
      )
    end

    before(:example) do
      stub_const('Queried', klass)

      klass.send(:include, Metasploit::Model::Search)
      klass.search_attribute :thing_one, :type => :string
      klass.search_attribute :thing_two, :type => :string
    end

    context 'root' do
      subject(:root) do
        tree
      end

      it { is_expected.to be_a Metasploit::Model::Search::Group::Intersection }

      context 'children' do
        subject(:children) do
          root.children
        end

        it 'should be an Array<Metasploit::Model::Search::Group::Union>' do
          children.each do |child|
            expect(child).to be_a Metasploit::Model::Search::Group::Union
          end
        end

        it 'should have same operator for each child of a union' do
          children.each do |child|
            operator_set = child.children.inject(Set.new) { |block_operator_set, operation|
              block_operator_set.add operation.operator
            }

            expect(operator_set.length).to eq(1)
          end
        end

        context 'grandchildren' do
          let(:grandchildren) do
            grandchildren = []

            children.each do |child|
              grandchildren.concat child.children
            end

            grandchildren
          end

          it 'should be Array<Metasploit::Model::Search::Operation::Base>' do
            grandchildren.each do |grandchild|
              expect(grandchild).to be_a Metasploit::Model::Search::Operation::Base
            end
          end
        end
      end
    end
  end

  context '#without_operator' do
    subject(:without_operator) do
      query.without_operator(filtered_operator)
    end

    #
    # lets
    #

    let(:attributes) do
      Array.new(2) { |i|
        "attribute_#{i}".to_sym
      }
    end

    let(:filtered_operator) do
      operators.sample
    end

    let(:klass) do
      Class.new
    end

    let(:operators) do
      attributes.collect { |attribute|
        klass.search_attribute attribute, type: :string
      }
    end

    let(:query) do
      described_class.new(
          formatted_operations: formatted_operations,
          klass: klass
      )
    end

    let(:unfiltered_operators) do
      operators - [filtered_operator]
    end

    #
    # Callbacks
    #

    before(:example) do
      stub_const('Queried', klass)

      klass.send(:include, Metasploit::Model::Search)
    end

    context 'with operator' do
      let(:formatted_operations) do
        operators.collect { |operator|
          "#{operator.name}:value"
        }
      end

      it 'should return a new query' do
        expect(without_operator).not_to be query
      end

      it 'should not have operations on the removed operator' do
        expect(without_operator.operations_by_operator[filtered_operator]).to be_blank
      end

      it 'should have same #klass as this query' do
        expect(without_operator.klass).to eq(query.klass)
      end

      context 'with no other operators' do
        let(:formatted_operations) do
          [
              "#{filtered_operator.name}:value"
          ]
        end

        it { is_expected.to_not be_valid }
      end

      context 'with other operators' do
        it { is_expected.to be_valid }
      end
    end

    context 'without operator' do
      let(:formatted_operations) do
        unfiltered_operators.collect { |operator|
          "#{operator.name}:value"
        }
      end

      it 'should return this query' do
        expect(without_operator).to be query
      end
    end
  end
end