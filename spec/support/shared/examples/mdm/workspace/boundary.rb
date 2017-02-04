RSpec.shared_examples_for 'Mdm::Workspace::Boundary' do
  context 'methods' do
    let(:boundary) do
      nil
    end

    before(:example) do
      workspace.boundary = boundary
    end

    context '#addresses' do
      subject(:addresses) do
        workspace.addresses
      end

      context 'with boundary' do
        let(:boundary) do
          expected_addresses.join("\n")
        end

        let(:expected_addresses) do
          [
            '10,10,10,10',
            '192.168.0.1'
          ]
        end

        it 'should return addresses split on newline' do
          expect(addresses).to eq(expected_addresses)
        end
      end

      context 'without boundary' do
        let(:boundary) do
          nil
        end

        it 'should return an empty Array' do
          expect(addresses).to eq([])
        end
      end
    end

    context '#boundary_must_be_ip_range' do
      let(:error) do
        'must be a valid IP range'
      end

      context 'with boundary' do
        let(:boundary) do
          '192.168.0.1'
        end

        it 'should split boundary' do
          expect(Shellwords).to receive(:split).with(boundary).and_call_original

          workspace.valid?
        end

        context 'with error from Shellwords.split' do
          before(:example) do
            allow(Shellwords).to receive(:split).with(boundary).and_raise(ArgumentError)
          end

          it 'should not raise error' do
            expect {
              workspace.valid?
            }.to_not raise_error
          end

          it 'should not record an error' do
            workspace.valid?

            expect(workspace.errors[:boundary]).not_to include(error)
          end
        end

        context 'with empty' do
          let(:boundary) do
            ''
          end

          it 'should not record an error' do
            workspace.valid?

            expect(workspace.errors[:boundary]).not_to include(error)
          end
        end

        context 'without empty' do
          let(:ranges) do
            [
              '10.10.10.10',
              '192.168.0.1'
            ]
          end

          let(:boundary) do
            ranges.join(' ')
          end

          it 'should validate each range' do
            ranges.each do |range|
              expect(workspace).to receive(:valid_ip_or_range?).with(range).and_call_original
            end

            workspace.valid?
          end

          context 'with invalid range' do
            let(:ranges) do
              [
                '192.168'
              ]
            end

            it 'should record error', :skip => 'https://www.pivotaltracker.com/story/show/43171927' do
              expect(workspace).not_to be_valid
              expect(workspace.errors[:boundary]).to include(error)
            end
          end
        end
      end

      context 'without boundary' do
        it 'should not record error' do
          workspace.valid?

          expect(workspace.errors[:boundary]).not_to include(error)
        end
      end
    end
  end
end