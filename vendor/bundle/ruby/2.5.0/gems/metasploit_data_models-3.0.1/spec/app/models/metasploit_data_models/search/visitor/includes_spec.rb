RSpec.describe MetasploitDataModels::Search::Visitor::Includes, type: :model do
  subject(:visitor) do
    described_class.new
  end

  it_should_behave_like 'Metasploit::Concern.run'

  context '#visit' do
    subject(:visit) do
      visitor.visit(node)
    end

    children_classes = [
        Metasploit::Model::Search::Group::Intersection,
        Metasploit::Model::Search::Group::Union,
        Metasploit::Model::Search::Operation::Group::Intersection,
        Metasploit::Model::Search::Operation::Group::Union
    ]

    children_classes.each do |children_class|
      context "with #{children_class}" do
        it_should_behave_like "MetasploitDataModels::Search::Visitor::Includes#visit with #children" do
          let(:node_class) do
            children_class
          end
        end
      end
    end

    context 'with Metasploit::Model::Search::Operation::Association' do
      let(:association) {
        :parent_association
      }

      let(:node) {
        operator.operate_on('formatted_value')
      }

      let(:operator) {
        Metasploit::Model::Search::Operator::Association.new(
            association: association,
            source_operator: source_operator
        )
      }

      context '#source_operation' do
        let(:attribute_operator) {
          Metasploit::Model::Search::Operator::Attribute.new(
              type: :string
          )
        }

        context 'with Metasploit::Model::Search::Operation::Association' do
          let(:source_operator) {
            Metasploit::Model::Search::Operator::Association.new(
                association: source_operator_association,
                source_operator: attribute_operator
            )
          }

          let(:source_operator_association) {
            :child_association
          }

          it 'is [{ association => nested associations }]' do
            expect(visit).to eq([{association => [source_operator_association]}])
          end
        end

        context 'without Metasploit::Model::Search::Operation::Association' do
          let(:source_operator) {
            attribute_operator
          }

          it 'is [association]' do
            expect(visit).to eq([association])
          end
        end
      end
    end

    operation_classes = [
        Metasploit::Model::Search::Operation::Boolean,
        Metasploit::Model::Search::Operation::Date,
        Metasploit::Model::Search::Operation::Integer,
        Metasploit::Model::Search::Operation::Null,
        Metasploit::Model::Search::Operation::Set::Integer,
        Metasploit::Model::Search::Operation::Set::String,
        Metasploit::Model::Search::Operation::String
    ]

    operation_classes.each do |operation_class|
      context "with #{operation_class}" do
        it_should_behave_like 'MetasploitDataModels::Search::Visitor::Includes#visit with Metasploit::Model::Search::Operation::Base' do
          let(:node_class) do
            operation_class
          end
        end
      end
    end

    context 'with Metasploit::Model::Search::Operator::Association' do
      let(:association) do
        FactoryBot.generate :metasploit_model_search_operator_association_association
      end

      let(:node) do
        Metasploit::Model::Search::Operator::Association.new(
            :association => association
        )
      end
    end

    context 'with Metasploit::Model::Search::Operator::Attribute' do
      let(:node) do
        Metasploit::Model::Search::Operator::Attribute.new
      end

      it { is_expected.to eq([]) }
    end

    context 'with MetasploitDataModels::Search::Operator::Port::List' do
      let(:node) do
        MetasploitDataModels::Search::Operator::Port::List.new
      end

      it { is_expected.to eq([]) }
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

      context 'Metasploit::Model::Search::Query#klass' do
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

            it { is_expected.to be_empty }
          end

          context 'with services.name' do
            let(:name) do
              FactoryBot.generate :mdm_service_name
            end

            let(:formatted) do
              "services.name:\"#{name}\""
            end

            it { is_expected.to include :services }
          end
        end
      end
    end
  end
end
