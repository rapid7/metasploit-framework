RSpec.describe Metasploit::Model::Search::Operation do
  context 'parse' do
    subject(:parse) do
      described_class.parse(options)
    end

    context 'with :formatted_operation' do
      let(:formatted_operation) do
        "#{formatted_operator}:#{formatted_value}"
      end

      let(:formatted_operator) do
        'operator'
      end

      let(:formatted_value) do
        'value'
      end

      let(:options) do
        {
            :formatted_operation => formatted_operation
        }
      end

      context 'with :query' do
        let(:operation) do
          double('Operation')
        end

        let(:operator) do
          double('Operator')
        end

        let(:options) do
          super().merge(
              {
                  :query => query
              }
          )
        end

        let(:query) do
          double('Metasploit::Model::Search::Query')
        end

        context "with at least one ':' in :formatted_operation" do
          before(:example) do
            allow(query).to receive(:parse_operator).with(formatted_operator).and_return(operator)
            allow(operator).to receive(:operate_on).with(formatted_value).and_return(operation)
          end

          context "with multiple ':' in :formatted_operation" do
            let(:formatted_value) do
              '1:2'
            end

            it "should treat portion before first ':' as formatted operator" do
              expect(query).to receive(:parse_operator).with(formatted_operator)

              parse
            end

            it "should treat portion after first ':' as formatted value including later ':'" do
              expect(operator).to receive(:operate_on).with(formatted_value)

              parse
            end
          end

          context "with single ':' in :formatted_operation" do
            let(:formatted_value) do
              '1'
            end

            it "should use portion before ':' as formatted operator" do
              expect(query).to receive(:parse_operator).with(formatted_operator)

              parse
            end

            it "should use portion after ':' as formatted value" do
              expect(operator).to receive(:operate_on).with(formatted_value)

              parse
            end
          end
        end

        context "without ':' in :formatted_operation" do
          let(:formatted_operation) do
            formatted_operator
          end

          let(:formatted_operator) do
            '1'
          end

          let(:formatted_value) do
            nil
          end

          it "should use entirety as formatted operator" do
            allow(operator).to receive(:operate_on).and_return(operation)

            expect(query).to receive(:parse_operator).with(formatted_operator).and_return(operator)

            parse
          end

          it "should use '' as formatted value instead of nil" do
            allow(query).to receive(:parse_operator).and_return(operator)

            expect(operator).to receive(:operate_on).with('')

            parse
          end
        end
      end

      context 'without :query' do
        it 'should raise KeyError' do
          expect {
            parse
          }.to raise_error(KeyError)
        end
      end
    end

    context 'without :formatted_operation' do
      let(:options) do
        {}
      end

      it 'should raise KeyError' do
        expect {
          parse
        }.to raise_error(KeyError)
      end
    end
  end
end