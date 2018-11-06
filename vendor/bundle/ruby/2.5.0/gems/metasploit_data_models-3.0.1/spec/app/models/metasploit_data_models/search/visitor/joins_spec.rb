RSpec.describe MetasploitDataModels::Search::Visitor::Joins, type: :model do
  subject(:visitor) do
    described_class.new
  end

  it_should_behave_like 'Metasploit::Concern.run'

  context '#visit' do
    subject(:visit) do
      visitor.visit(node)
    end

    intersection_classes = [
        Metasploit::Model::Search::Group::Intersection,
        Metasploit::Model::Search::Operation::Group::Intersection
    ]

    intersection_classes.each do |intersection_class|
      context "with #{intersection_class}" do
        let(:children) do
          2.times.collect { |n|
            double("Child #{n}")
          }
        end

        let(:node) do
          intersection_class.new(
              :children => children
          )
        end

        it 'should visit each child' do
          # needed for call to visit subject
          expect(visitor).to receive(:visit).with(node).and_call_original

          children.each do |child|
            expect(visitor).to receive(:visit).with(child).and_return([])
          end

          visit
        end

        it 'should return Array of all child visits' do
          child_visits = []

          expect(visitor).to receive(:visit).with(node).and_call_original

          children.each_with_index do |child, i|
            child_visit = ["Visited Child #{i}"]
            allow(visitor).to receive(:visit).with(child).and_return(child_visit)
            child_visits.concat(child_visit)
          end

          expect(visit).to eq(child_visits)
        end
      end
    end

    union_classes = [
        Metasploit::Model::Search::Group::Union,
        Metasploit::Model::Search::Operation::Group::Union
    ]

    union_classes.each do |union_class|
      context "with #{union_class}" do
        let(:node) do
          union_class.new(
              children: children
          )
        end

        context 'with children' do
          context 'without child joins' do
            let(:children) do
              Array.new(2) {
                operator = Metasploit::Model::Search::Operator::Attribute.new(type: :string)

                operator.operate_on('formatted_value')
              }
            end

            it { is_expected.to eq([]) }
          end

          context 'with association and attribute', pending: 'FactoryBot update' do
            let(:association) do
              FactoryBot.generate :metasploit_model_search_operator_association_association
            end

            let(:association_operation) {
              association_operator.operate_on('formatted_value')
            }

            let(:association_operator) do
              source_operator = Metasploit::Model::Search::Operator::Attribute.new(type: :string)

              Metasploit::Model::Search::Operator::Association.new(
                  association: association,
                  source_operator: source_operator
              )
            end

            let(:attribute_operation) {
              attribute_operator.operate_on('formatted_value')
            }

            let(:attribute_operator) do
              Metasploit::Model::Search::Operator::Attribute.new(type: :string)
            end

            let(:children) do
              [
                  association_operation,
                  attribute_operation
              ]
            end

            it { is_expected.to eq([]) }
          end

          context 'with the same child join for all', pending: "FactoryBot update" do
            let(:association) do
              FactoryBot.generate :metasploit_model_search_operator_association_association
            end

            let(:association_operation) {
              association_operator.operate_on('formatted_value')
            }

            let(:association_operator) do
              source_operator = Metasploit::Model::Search::Operator::Attribute.new(type: :string)

              Metasploit::Model::Search::Operator::Association.new(
                  association: association,
                  source_operator: source_operator
              )
            end

            let(:children) do
              Array.new(2) {
                association_operation
              }
            end

            it 'should include association' do
              expect(visit).to include association
            end
          end

          context 'with union of intersections', pending: "FactoryBot update" do
            let(:disjoint_associations) do
              Array.new(2) {
                FactoryBot.generate :metasploit_model_search_operator_association_association
              }
            end

            let(:first_associations) do
              disjoint_associations[0, 1] + common_associations
            end

            let(:first_association_operations) {
              first_association_operators.map { |association_operator|
                association_operator.operate_on('formatted_value')
              }
            }

            let(:first_association_operators) do
              first_associations.collect { |association|
                source_operator = Metasploit::Model::Search::Operator::Attribute.new(type: :string)

                Metasploit::Model::Search::Operator::Association.new(
                    association: association,
                    source_operator: source_operator
                )
              }
            end

            let(:second_associations) do
              disjoint_associations[1, 1] + common_associations
            end

            let(:second_association_operations) {
              second_association_operators.map { |association_operator|
                association_operator.operate_on('formatted_value')
              }
            }

            let(:second_association_operators) do
              second_associations.collect { |association|
                source_operator = Metasploit::Model::Search::Operator::Attribute.new(type: :string)

                Metasploit::Model::Search::Operator::Association.new(
                    association: association,
                    source_operator: source_operator
                )
              }
            end

            let(:children) do
              [first_association_operations, second_association_operations].collect { |grandchildren|
                Metasploit::Model::Search::Group::Intersection.new(
                    children: grandchildren
                )
              }
            end

            context 'with a common subset of child join' do
              let(:common_associations) do
                Array.new(2) {
                  FactoryBot.generate :metasploit_model_search_operator_association_association
                }
              end

              it 'should include common associations' do
                common_associations.each do |association|
                  expect(visit).to include(association)
                end
              end

              it 'should not include disjoint associations' do
                disjoint_associations.each do |association|
                  expect(visit).not_to include(association)
                end
              end
            end

            context 'without a common subset of child joins' do
              let(:common_associations) do
                []
              end

              it { is_expected.to eq([]) }
            end
          end
        end

        context 'without children' do
          let(:children) do
            []
          end

          it { is_expected.to eq([]) }
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

    context 'with Metasploit::Model::Search::Operator::Association', pending: "FactoryBot update" do
      let(:association) do
        FactoryBot.generate :metasploit_model_search_operator_association_association
      end

      let(:node) do
        Metasploit::Model::Search::Operator::Association.new(
            :association => association
        )
      end

      it 'is #association' do
        expect(visit).to eq(association)
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

      context 'Metasploit::Model::Search:Query#klass' do
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
