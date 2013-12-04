shared_examples_for 'Metasploit::Framework::Module::Ancestor::Namespace#module_ancestor_eval true' do
  it 'should save module_ancestor' do
    expect {
      module_ancestor_eval
    }.to change(Mdm::Module::Ancestor, :count)
  end

  it { should be_true }
end
