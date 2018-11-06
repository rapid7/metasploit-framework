RSpec.describe Metasploit::Model::Search::Association do
  subject(:base_class) do
    described_class = self.described_class

    Class.new do
      include described_class
    end
  end

  context 'search_association' do
    subject(:search_association) {
      base_class.search_association association
    }

    let(:association) {
      :root_association
    }

    context 'with previous call to search_association with same association' do
      before(:example) do
        base_class.search_association association
      end

      it 'does not change search_association_tree' do
        expect {
          search_association
        }.not_to change(base_class, :search_association_tree)
      end
    end

    context 'with association tree rooted on association' do
      before(:example) do
        base_class.search_associations association => :child_association
      end

      it 'leaves the original association tree in place' do
        expect {
          search_association
        }.not_to change(base_class, :search_association_tree)
      end
    end

    context 'without association in search_association_tree' do
      it 'adds association to search_association_tree with nil children' do
        search_association

        search_association_tree = base_class.search_association_tree

        expect(search_association_tree).to have_key(association)
        expect(search_association_tree[association]).to be_nil
      end
    end
  end

  context 'search_associations' do
    subject(:search_associations) {
      base_class.search_associations(*associations)
    }

    let(:associations) {
      [
        :association
      ]
    }

    let(:expanded_associations) {
      {
          association: nil
      }
    }

    it 'expands associations' do
      expect(Metasploit::Model::Association::Tree).to receive(:expand).with(associations).and_return(
                                                          expanded_associations
                                                      )

      search_associations
    end

    it 'merges the expanded associations with the current search_association_tree' do
      expect(Metasploit::Model::Association::Tree).to receive(:expand).and_return(expanded_associations)

      search_association_tree = {preexisting: nil}
      expect(base_class).to receive(:search_association_tree).and_return(search_association_tree)

      expect(Metasploit::Model::Association::Tree).to receive(:merge).with(
                                                          search_association_tree,
                                                          expanded_associations
                                                      )

      search_associations
    end
  end

  context 'search_association_operators' do
    subject(:search_association_operators) {
      base_class.search_association_operators
    }

    let(:search_association_tree) {
      {
          parent: {
              child: nil
          }
      }
    }

    it 'converts search_association_tree to operators' do
      expect(base_class).to receive(:search_association_tree).and_return(search_association_tree)
      expect(Metasploit::Model::Association::Tree).to receive(:operators).with(
                                                          search_association_tree,
                                                          hash_including(
                                                              class: base_class
                                                          )
                                                      )

      search_association_operators
    end
  end
end