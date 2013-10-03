shared_examples_for 'Msf::ModuleManager::ModuleSets' do
  context '#auxiliary' do
    subject(:auxiliary) do
      module_manager.auxiliary
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'auxiliary' }
  end

  context '#encoders' do
    subject(:encoders) do
      module_manager.encoders
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'encoder' }
  end

  context '#exploits' do
    subject(:exploits) do
      module_manager.exploits
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'exploit' }
  end

  context '#nops' do
    subject(:nops) do
      module_manager.nops
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'nop' }
  end

  context '#payloads' do
    subject(:payloads) do
      module_manager.payloads
    end

    it { should be_a Msf::PayloadSet }
    its(:module_type) { should == 'payload' }
  end

  context '#post' do
    subject(:post) do
      module_manager.post
    end

    it { should be_a Msf::ModuleSet }
    its(:module_type) { should == 'post' }
  end
end