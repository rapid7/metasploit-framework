RSpec.shared_examples_for 'Msf::Module::Author' do
  it { is_expected.to respond_to :author }
  it { is_expected.to respond_to :author_to_s }
  it { is_expected.to respond_to :each_author }
end
