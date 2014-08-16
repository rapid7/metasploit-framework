shared_context 'Msf::DBManager' do
  include_context 'Msf::Simple::Framework'

  let(:active) do
    true
  end

  let(:db_manager) do
    framework.db
  end

  before(:each) do
    # already connected due to use_transactional_fixtures, but need some of the side-effects of #connect
    framework.db.workspace = framework.db.default_workspace
    db_manager.stub(:active => active)
  end
end