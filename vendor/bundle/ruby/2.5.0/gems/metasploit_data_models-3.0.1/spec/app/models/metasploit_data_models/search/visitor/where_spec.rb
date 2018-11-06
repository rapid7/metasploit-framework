RSpec.describe MetasploitDataModels::Search::Visitor::Where, type: :model do
  subject(:visitor) do
    described_class.new
  end

  it_should_behave_like 'Metasploit::Concern.run'

  context '#attribute_visitor' do
    subject(:attribute_visitor) do
      visitor.attribute_visitor
    end

    it { is_expected.to be_a MetasploitDataModels::Search::Visitor::Attribute }
  end

  context '#method_visitor' do
    subject(:method_visitor) do
      visitor.method_visitor
    end

    it { is_expected.to be_a MetasploitDataModels::Search::Visitor::Method }
  end

  context '#visit' do
    subject(:visit) do
      visitor.visit(node)
    end

    arel_class_by_group_class = {
        Metasploit::Model::Search::Group::Intersection => Arel::Nodes::And,
        Metasploit::Model::Search::Group::Union => Arel::Nodes::Or,
        Metasploit::Model::Search::Operation::Group::Intersection => Arel::Nodes::And,
        Metasploit::Model::Search::Operation::Group::Union => Arel::Nodes::Or
    }

    arel_class_by_group_class.each do |group_class, arel_class|
      context "with #{group_class}" do
        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Where#visit with Metasploit::Model::Search*::Group::Base',
                              :arel_class => arel_class do
          let(:node_class) do
            group_class
          end
        end
      end
    end

    equality_operation_classes = [
        Metasploit::Model::Search::Operation::Boolean,
        Metasploit::Model::Search::Operation::Date,
        Metasploit::Model::Search::Operation::Integer,
        Metasploit::Model::Search::Operation::Set::Integer,
        Metasploit::Model::Search::Operation::Set::String
    ]

    equality_operation_classes.each do |operation_class|
      context "with #{operation_class}" do
        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Where#visit with equality operation' do
          let(:node_class) do
            operation_class
          end
        end
      end
    end

    context 'with Metasploit::Model::Search::Operation::String' do
      let(:node) do
        Metasploit::Model::Search::Operation::String.new(
            :operator => operator,
            :value => value
        )
      end

      let(:operator) do
        Metasploit::Model::Search::Operator::Attribute.new(
            :klass => Mdm::Host,
            :attribute => :name
        )
      end

      let(:value) do
        'metasploitable'
      end

      it 'should visit operation.operator with attribute_visitor' do
        expect(visitor.attribute_visitor).to receive(:visit).with(operator).and_call_original

        visit
      end

      it 'should call matches on Arel::Attributes::Attribute from attribute_visitor' do
        attribute = double('Visited Operator')
        allow(visitor.attribute_visitor).to receive(:visit).with(operator).and_return(attribute)

        expect(attribute).to receive(:matches).with("%#{value}%")

        visit
      end
    end

    context 'with MetasploitDataModels::Search::Operation::Port::Range' do
      let(:node) {
        MetasploitDataModels::Search::Operation::Port::Range.new(
            operator: operator,
            value: value
        )
      }

      let(:operator) {
        MetasploitDataModels::Search::Operator::Port::List.new(
            klass: Mdm::Service
        )
      }

      let(:range) {
        1..2
      }

      let(:value) {
        "#{range.begin}-#{range.end}"
      }

      it 'should visit operation.operator with attribute_visitor' do
        expect(visitor.attribute_visitor).to receive(:visit).with(operator).and_call_original

        visit
      end

      it 'should call in on Arel::Attributes::Attribute from attribute_visitor' do
        attribute = double('Visited Operator')
        allow(visitor.attribute_visitor).to receive(:visit).with(operator).and_return(attribute)

        expect(attribute).to receive(:in).with(range)

        visit
      end
    end

    context 'with Metasploit::Model::Search::Query#tree' do
      let(:node) do
        query.tree
      end

      let(:query) do
        Metasploit::Model::Search::Query.new(
            :formatted => formatted,
            :klass => klass
        )
      end

      context 'with Metasploit::model::Search::Query#klass' do
        context 'with Mdm::Host' do
          let(:klass) {
            Mdm::Host
          }

          context 'with name' do
            let(:name) do
              FactoryBot.generate :mdm_host_name
            end

            let(:formatted) do
              "name:\"#{name}\""
            end

            it 'should match module_instances.name with ILIKE' do
              expect(visit.to_sql).to eq("\"hosts\".\"name\" ILIKE '%#{name}%'")
            end
          end

          context 'with services.name' do
            let(:name) do
              FactoryBot.generate :mdm_service_name
            end

            let(:formatted) do
              "services.name:\"#{name}\""
            end

            it 'should match module_actions.name with ILIKE' do
              expect(visit.to_sql).to eq("\"services\".\"name\" ILIKE '%#{name}%'")
            end
          end
        end
      end
    end
  end
end
