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

        it 'should validate using #valid_ip_or_range?' do
          expect(workspace).to receive(:valid_ip_or_range?).with(boundary).and_return(false)

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
end
