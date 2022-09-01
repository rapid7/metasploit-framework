RSpec.describe Mdm::Workspace, type: :model do
  subject(:workspace) do
    Mdm::Workspace.new
  end

  context 'validations' do
    context 'boundary' do
      let(:boundary) do
        nil
      end

      let(:error) do
        'must be a valid IP range'
      end

      context 'when the workspace is limited to a network' do
        before(:example) do
          workspace.boundary = boundary
          workspace.limit_to_network = true
          workspace.valid?
        end

        it 'should validate using #boundary_must_be_ip_range' do
          expect(workspace).to receive(:boundary_must_be_ip_range).and_return(false)

          workspace.valid?
        end

        context 'with valid IP' do
          let(:boundary) do
            '192.168.0.1'
          end

          it 'should not record an error' do
            expect(workspace.errors[:boundary]).not_to include(error)
          end
        end

        context 'with valid range' do
          let(:boundary) do
            '192.168.0.1/24'
          end

          it 'should not record an error' do
            expect(workspace.errors[:boundary]).not_to include(error)
          end
        end

        context 'with invalid IP or range' do
          let(:boundary) do
            '192.168'
          end

          it 'should record error that boundary must be a valid IP range' do
            expect(workspace).not_to be_valid
            expect(workspace.errors[:boundary]).to include(error)
          end
        end
      end

      context 'when the workspace is not network limited' do
        before(:example) do
          workspace.boundary = boundary
          workspace.valid?
        end

        it 'should not care about the value of the boundary' do
          expect(workspace.errors[:boundary]).not_to include(error)
        end
      end
    end
  end

  context 'methods' do
    context '#valid_ip_or_range?' do
      let(:ip_or_range) do
        nil
      end

      subject(:valid_ip_or_range?) { workspace.send(:valid_ip_or_range?, ip_or_range) }

      context 'with exception from Rex::Socket::RangeWalker' do
        before(:example) do
          allow(Rex::Socket::RangeWalker).to receive(:new).with(ip_or_range).and_raise(StandardError)
        end

        it { expect { valid_ip_or_range? }.to raise_error(StandardError) }
      end

      context 'without exception from Rex::Socket::RangeWalker' do
        context 'with valid IP' do
          let(:ip_or_range) do
            '192.168.0.1'
          end

          it { expect(valid_ip_or_range?).to be_truthy }
        end
      end
    end
  end


  it_should_behave_like 'Mdm::Workspace::Boundary'
end
