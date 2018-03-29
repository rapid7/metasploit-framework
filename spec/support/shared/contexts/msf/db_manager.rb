RSpec.shared_context 'Msf::DBManager' do
  include_context 'Msf::Simple::Framework'

  let(:active) do
    true
  end

  let(:db_manager) do
    framework.db.get_data_service
  end

  before(:example) do
    # already connected due to use_transactional_fixtures, but need some of the side-effects of #connect
    db_manager.workspace = db_manager.default_workspace
    allow(db_manager).to receive(:active).and_return(active)
  end
end
