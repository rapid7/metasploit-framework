require 'rspec'

RSpec.describe 'Lotus Domino Hashes' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/lotus/lotus_domino_hashes'
    )
  end
  let(:view_id) do
    Faker::Number.new
  end
  let(:cookie) do
    'invalid'
  end
  let(:uri) do
    'http'
  end
  let(:workspace) do
    FactoryBot.create(:mdm_workspace)
  end
  let(:service) do
    FactoryBot.create(:mdm_service, host: FactoryBot.create(:mdm_host, workspace: workspace))
  end
  let(:result) do
    resp = double(Rex::Proto::Http::Response)
    allow(resp).to receive(:body).and_return(mock_doc_data)
    allow(resp).to receive(:get_html_document).and_return(Nokogiri::XML(mock_doc_data))
    resp
  end
  let(:mock_doc_data) do
    File.binread(mock_doc)
  end
  let(:mock_doc) do
    File.expand_path('lotus_domino_hash_response.xml', FILE_FIXTURES_PATH + 'modules/auxiliary/')
  end

  before do
    allow(subject).to receive(:send_request_raw).and_return(result)
    allow(subject).to receive(:report_service).and_return(service)
    allow(subject).to receive(:report_auth_info)
  end

  describe '#dump_hashes' do
    it 'when provided valid XML' do
      subject.dump_hashes(view_id, cookie, uri)
      expect(subject).to have_received(:report_auth_info).with(hash_including({ user: 'Bdn Alln', pass: '(Da2Bd765Be64aF01b5652ce32eaA283d)', proof: a_string_matching(/NULL/) }))
    end

    describe 'incomplete XML' do
      let(:mock_doc) do
        File.expand_path('lotus_domino_hash_response_no_cred.xml', FILE_FIXTURES_PATH + 'modules/auxiliary/')
      end
      it 'when provided valid XML missing a credential' do
        subject.dump_hashes(view_id, cookie, uri)
        expect(subject).not_to have_received(:report_auth_info)
      end
    end
  end
end
