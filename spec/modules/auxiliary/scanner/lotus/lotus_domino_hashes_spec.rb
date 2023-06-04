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
    'mock-cookie'
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
    instance_double(
      Rex::Proto::Http::Response,
      body: mock_doc_data,
      get_html_document: Nokogiri::XML(mock_doc_data)
    )
  end
  let(:mock_doc_data) do
    File.binread(mock_doc)
  end
  let(:mock_doc) do
    File.join(FILE_FIXTURES_PATH, 'modules', 'auxiliary', 'lotus_domino_hash_response.xml')
  end

  before(:each) do
    allow(subject).to receive(:send_request_raw).and_return(result)
    allow(subject).to receive(:report_service).and_return(service)
    allow(subject).to receive(:report_auth_info)
  end

  describe '#dump_hashes' do
    context 'when the service response contains credentials' do
      context 'when the database is connected' do
        it 'reports the extracted user and password' do
          subject.dump_hashes(view_id, cookie, uri)
          expect(subject).to have_received(:report_auth_info).with(hash_including({ user: 'Bdn Alln', pass: '(Da2Bd765Be64aF01b5652ce32eaA283d)', proof: a_string_matching(/USER_MAIL=NULL/) }))
        end
      end

      context 'when report_service returns nil due to not having a database connected', skip_before: true do
        before(:each) do
          allow(subject).to receive(:report_service).and_return(nil)
        end

        it 'reports the extracted user and password' do
          subject.dump_hashes(view_id, cookie, uri)
          expect(subject).to have_received(:report_auth_info).with(hash_including({ user: 'Bdn Alln', pass: '(Da2Bd765Be64aF01b5652ce32eaA283d)', proof: a_string_matching(/USER_MAIL=NULL/) }))
        end
      end
    end

    context 'when the service response does not contain credentials' do
      let(:mock_doc) do
        File.join(FILE_FIXTURES_PATH, 'modules', 'auxiliary', 'lotus_domino_hash_response_no_cred.xml')
      end
      it 'when provided valid XML missing a credential' do
        subject.dump_hashes(view_id, cookie, uri)
        expect(subject).not_to have_received(:report_auth_info)
      end
    end
  end
end
