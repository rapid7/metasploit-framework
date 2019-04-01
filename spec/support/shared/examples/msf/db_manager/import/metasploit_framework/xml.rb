# -*- coding:binary -*-
require 'builder'

RSpec.shared_examples_for 'Msf::DBManager::Import::MetasploitFramework::XML' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting a port of all components")}
  end

  # Serialized format from pro/modules/auxiliary/pro/report.rb
  def serialize(object)
    # FIXME https://www.pivotaltracker.com/story/show/46578647
    marshalled = Marshal.dump(object)
    base64_encoded = [marshalled].pack('m')
    compact = base64_encoded.gsub(/\s+/, '')

    compact
  end

  def with_info
    expect(db_manager).to receive(:import_msf_web_element) do |*args, &specialization|
      info = specialization.call(element, options)

      yield info
    end

    subject
  end

  let(:allow_yaml) do
    false
  end

  let(:document) do
    Nokogiri::XML::Reader.from_memory(source)
  end

  let(:element) do
    nil
  end

  let(:host_attributes) do
    FactoryBot.attributes_for(:mdm_host)
  end

  let(:msf_web_text_element_names) do
    [
        'created-at',
        'host',
        'path',
        'port',
        'query',
        'ssl',
        'updated-at',
        'vhost'
    ]
  end

  let(:notifier) do
    lambda do |event, data|

    end
  end

  let(:options) do
    {
        :allow_yaml => allow_yaml,
        :workspace => workspace
    }
  end

  let(:service_attributes) do
    FactoryBot.attributes_for(:web_service)
  end

  let(:web_form_attributes) do
    FactoryBot.attributes_for(:mdm_web_form, :exported)
  end

  let(:web_page_attributes) do
    FactoryBot.attributes_for(:mdm_web_page)
  end

  let(:workspace) do
    nil
  end

  let(:xml) do
    Builder::XmlMarkup.new(:indent => 2)
  end

  it 'should include methods from module so method can be overridden easier in pro' do
    expect(db_manager).to be_a Msf::DBManager::Import::MetasploitFramework::XML
  end

  context 'CONSTANTS' do
    it 'should define MSF_WEB_PAGE_TEXT_ELEMENT_NAMES in any order' do
      described_class::MSF_WEB_PAGE_TEXT_ELEMENT_NAMES =~ [
          'auth',
          'body',
          'code',
          'cookie',
          'ctype',
          'location',
          'mtime'
      ]
    end

    it 'should define MSF_WEB_TEXT_ELEMENT_NAMES in any order' do
      described_class::MSF_WEB_TEXT_ELEMENT_NAMES =~ msf_web_text_element_names
    end

    it 'should define MSF_WEB_VULN_TEXT_ELEMENT_NAMES in any order' do
      described_class::MSF_WEB_VULN_TEXT_ELEMENT_NAMES =~ [
          'blame',
          'category',
          'confidence',
          'description',
          'method',
          'name',
          'pname',
          'proof',
          'risk'
      ]
    end
  end

  context '#check_msf_xml_version!' do
    let(:root_tag) do
      'root'
    end

    let(:source) do
      xml.tag!(root_tag)

      xml.target!
    end

    subject(:metadata) do
      db_manager.send(:check_msf_xml_version!, Nokogiri::XML(document.source).elements.first.name)
    end

    it_should_behave_like(
        'Msf::DBManager::Import::MetasploitFramework::XML#check_msf_xml_version! with root tag',
        'MetasploitExpressV1',
        :allow_yaml => true
    )

    it_should_behave_like(
        'Msf::DBManager::Import::MetasploitFramework::XML#check_msf_xml_version! with root tag',
        'MetasploitExpressV2',
        :allow_yaml => true
    )

    it_should_behave_like(
        'Msf::DBManager::Import::MetasploitFramework::XML#check_msf_xml_version! with root tag',
        'MetasploitExpressV3',
        :allow_yaml => false
    )

    it_should_behave_like(
        'Msf::DBManager::Import::MetasploitFramework::XML#check_msf_xml_version! with root tag',
        'MetasploitExpressV4',
        :allow_yaml => false
    )

    context 'with other' do
      it 'should raise Msf::DBImportError' do
        expect {
          metadata
        }.to raise_error(
                 Msf::DBImportError,
                 'Unsupported Metasploit XML document format'
             )
      end
    end
  end

  it { is_expected.to respond_to :import_msf_file }

  context '#import_msf_text_element' do
    let(:parent_element) do
      Nokogiri::XML(document.source).elements.first
    end

    let(:child_name) do
      'child'
    end

    let(:child_sym) do
      child_name.to_sym
    end

    subject(:info) do
      db_manager.send(:import_msf_text_element, parent_element, child_name)
    end

    context 'with child element' do
      let(:source) do
        xml.parent do
          xml.tag!(child_name, text)
        end

        xml.target!
      end

      context 'with padded text' do
        let(:stripped) do
          'stripped'
        end

        let(:text) do
          "  #{stripped} "
        end

        it 'should strip text' do
          expect(info[:child]).to eq stripped
        end
      end

      context 'with NULL text' do
        let(:text) do
          'NULL'
        end

        it 'should have nil for child name in info' do
          # use have_key to verify info isn't just returning hash default of
          # `nil`.
          expect(info).to have_key(child_sym)
          expect(info[child_sym]).to be_nil
        end
      end

      context 'without NULL text' do
        let(:text) do
          'some text'
        end

        it 'should have text for child name in info' do
          expect(info[child_sym]).to eq text
        end
      end
    end

    context 'without child element' do
      let(:source) do
        xml.parent

        xml.target!
      end

      it 'should return an empty Hash' do
        expect(info).to eq({})
      end
    end
  end

  context 'import_msf_web_element' do
    let(:element) do
      Nokogiri::XML(document.source).elements.first
    end

    let(:options) do
      {}
    end

    let(:specialization) do
      lambda { |element, options|
        {}
      }
    end

    subject(:import_msf_web_element) do
      db_manager.send(
          :import_msf_web_element,
          element,
          options,
          &specialization
      )
    end

    context 'with :type' do
      let(:source) do
        xml.tag!("web_#{type}") do
          web_site = web_vuln.web_site
          service = web_site.service

          xml.host(service.host.address)
          xml.path(web_vuln.path)
          xml.port(service.port)
          xml.query(web_vuln.query)

          ssl = false

          if service.name == 'https'
            ssl = true
          end

          xml.ssl(ssl)

          xml.vhost(web_site.vhost)
        end

        xml.target!
      end

      let(:type) do
        :vuln
      end

      let(:web_vuln) do
        FactoryBot.create(:mdm_web_vuln)
      end

      before(:example) do
        allow(db_manager).to receive(
            :report_web_vuln
        ).with(
            an_instance_of(Hash)
        )

        options[:type] = type
      end

      context 'with :workspace' do
        let(:workspace) do
          double(':workspace')
        end

        before(:example) do
          options[:workspace] = workspace
        end

        it 'should not call Msf::DBManager#workspace' do
          expect(db_manager).not_to receive(:workspace)

          import_msf_web_element
        end

        it 'should pass :workspace to report_web_<:type>' do
          expect(db_manager).to receive(
              "report_web_#{type}"
          ).with(
              hash_including(:workspace => workspace)
          )

          import_msf_web_element
        end
      end

      context 'without :workspace' do
        let(:workspace) do
          FactoryBot.create(:mdm_workspace)
        end

        before(:example) do
          db_manager.workspace = workspace
        end

        it 'should call Msf::DBManager#workspace' do
          expect(db_manager).to receive(:workspace).and_call_original

          import_msf_web_element
        end

        it 'should pass Msf::DBManager#workspace to report_web_<:type>' do
          expect(db_manager).to receive(
              "report_web_#{type}"
          ).with(
              hash_including(:workspace => workspace)
          )

          import_msf_web_element
        end
      end

      it 'should import all elements in MSF_WEB_TEXT_ELEMENT_NAMES with #import_msf_text_element' do
        msf_web_text_element_names.each do |name|
          expect(db_manager).to receive(
              :import_msf_text_element
          ).with(
              element,
              name
          ).and_call_original
        end

        import_msf_web_element
      end

      context 'with non-empty Hash from #import_msf_text_element' do
        let(:returned_hash) do
          {
              :host => '192.168.0.1'
          }
        end

        before(:example) do
          allow(db_manager).to receive(:import_msf_text_element).and_return(returned_hash)
        end

        it 'should pass returned Hash as part of Hash passed to report_web_<:type' do
          expect(db_manager).to receive(
              "report_web_#{type}"
          ).with(
              hash_including(returned_hash)
          )

          import_msf_web_element
        end
      end

      context 'ssl element' do
        context 'without element' do
          let(:source) do
            xml.tag!("web_#{type}")

            xml.target!
          end

          it 'should pass false for :ssl to report_web_<:type>' do
            expect(db_manager).to receive(
                "report_web_#{type}"
            ).with(
                hash_including(:ssl => false)
            )

            import_msf_web_element
          end
        end

        context 'with element' do
          let(:source) do
            xml.tag!("web_#{type}") do
              xml.ssl(ssl)
            end

            xml.target!
          end

          context "with 'true' text" do
            let(:ssl) do
              true
            end

            it 'should pass true for :ssl to report_web_<:type>' do
              expect(db_manager).to receive(
                  "report_web_#{type}"
              ).with(
                  hash_including(:ssl => true)
              )

              import_msf_web_element
            end
          end

          context "without 'true' text" do
            let(:ssl) do
              false
            end

            it 'should pass false for :ssl to report_web_<:type>' do
              expect(db_manager).to receive(
                  "report_web_#{type}"
              ).with(
                  hash_including(:ssl => false)
              )

              import_msf_web_element
            end
          end
        end
      end

      context 'specialization block' do
        let(:returned_hash) do
          {
              :specialized => double('Value')
          }
        end

        let(:specialization) do
          lambda { |element, option|
            returned_hash
          }
        end

        it 'should be called with element and options' do
          actual_args = []

          db_manager.send(
              :import_msf_web_element,
              element,
              options) do |*args|
            actual_args = args

            returned_hash
          end

          expect(actual_args).to eq [element, options]
        end

        it 'should pass return Hash to report_web_<:type>' do
          expect(db_manager).to receive(
              "report_web_#{type}"
          ).with(
              hash_including(returned_hash)
          )

          import_msf_web_element
        end
      end

      context 'notifier' do
        context 'with :notifier' do
          let(:event) do
            "web_#{type}".to_sym
          end

          let(:notifier) do
            lambda do |*args|
              successive_args << args
            end
          end

          let(:successive_args) do
            []
          end

          before(:example) do
            options[:notifier] = notifier
          end

          it 'should call :notifier with event and path' do
            import_msf_web_element

            expect(successive_args.length).to eq 1

            args = successive_args[0]

            expect(args.length).to eq 2
            expect(args[0]).to eq event
            expect(args[1]).to eq web_vuln.path
          end
        end

        context 'without :notifier' do
          it 'should not raise an error' do
            expect {
              import_msf_web_element
            }.to_not raise_error
          end
        end
      end
    end

    context 'without :type' do
      let(:element) do
        nil
      end

      it 'should raise KeyError' do
        expect {
          import_msf_web_element
        }.to raise_error(KeyError, 'key not found: :type')
      end
    end
  end

  context '#import_msf_web_form_element' do
    let(:type) do
      :form
    end

    subject(:import_msf_web_form_element) do
      db_manager.import_msf_web_form_element(
          element,
          options,
          &notifier
      )
    end

    context 'call to #import_msf_web_element' do

      it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::XML#import_msf_web_element specialization'

      context 'specialization return' do
        let(:element) do
          Nokogiri::XML(document.source).elements.first
        end

        let(:source) do
          xml.web_form do
            xml.method(
                web_form_attributes.fetch(:method)
            )

            serialized_params = serialize(
                web_form_attributes.fetch(:params)
            )
            xml.params(serialized_params)
          end

          xml.target!
        end

        it 'should be a Hash' do
          with_info do |info|
            expect(info).to be_a Hash
          end
        end

        it 'should include :method' do
          with_info do |info|
            expect(info[:method]).to eq web_form_attributes[:method]
          end
        end

        it 'should include :params' do
          with_info do |info|
            expect(info[:params]).to eq web_form_attributes[:params]
          end
        end
      end
    end

    context 'with required attributes' do
      let(:element) do
        Nokogiri::XML(document.source).elements.first
      end

      let(:source) do
        xml.web_form do
          xml.host(
              host_attributes.fetch(:address)
          )
          xml.method(
              web_form_attributes.fetch(:method)
          )
          xml.path(
              web_form_attributes.fetch(:path)
          )
          xml.port(
              service_attributes.fetch(:port)
          )

          ssl = false

          if service_attributes[:name] == 'https'
            ssl = true
          end

          xml.ssl(ssl)
        end

        xml.target!
      end

      it 'should create an Mdm::WebForm' do
        expect {
          import_msf_web_form_element
        }.to change(Mdm::WebForm, :count).by(1)
      end
    end
  end

  context '#import_msf_web_page_element' do
    let(:type) do
      :page
    end

    subject(:import_msf_web_page_element) do
      db_manager.import_msf_web_page_element(
          element,
          options,
          &notifier
      )
    end

    context 'call to #import_msf_web_element' do
      it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::XML#import_msf_web_element specialization'

      context 'specialization return' do
        let(:element) do
          Nokogiri::XML(document.source).elements.first
        end

        let(:source) do
          xml.web_page do
            xml.auth(
                web_page_attributes.fetch(:auth)
            )
            xml.body(
                web_page_attributes.fetch(:body)
            )
            xml.code(
                web_page_attributes.fetch(:code)
            )
            xml.cookie(
                web_page_attributes.fetch(:cookie)
            )
            xml.ctype(
                web_page_attributes.fetch(:ctype)
            )

            serialized_headers = serialize(
                web_page_attributes.fetch(:headers)
            )
            xml.headers(serialized_headers)

            xml.location(
                web_page_attributes.fetch(:location)
            )
            xml.mtime(
                web_page_attributes.fetch(:mtime)
            )
          end

          xml.target!
        end

        it 'should be a Hash' do
          expect(db_manager).to receive(:import_msf_web_element) do |*args, &specialization|
            info = specialization.call(element, options)

            expect(info).to be_a Hash
          end

          import_msf_web_page_element
        end

        it 'should include :auth' do
          with_info do |info|
            expect(info[:auth]).to eq web_page_attributes.fetch(:auth)
          end
        end

        it 'should include :body' do
          with_info do |info|
            expect(info[:body]).to eq web_page_attributes.fetch(:body)
          end
        end

        it 'should include :code' do
          with_info do |info|
            expect(info[:code]).to eq web_page_attributes.fetch(:code)
          end
        end

        it 'should include :cookie' do
          with_info do |info|
            expect(info[:cookie]).to eq web_page_attributes.fetch(:cookie)
          end
        end

        it 'should include :ctype' do
          with_info do |info|
            expect(info[:ctype]).to eq web_page_attributes.fetch(:ctype)
          end
        end

        it 'should include :headers' do
          with_info do |info|
            expect(info[:headers]).to eq web_page_attributes.fetch(:headers)
          end
        end

        it 'should include :location' do
          with_info do |info|
            expect(info[:location]).to eq web_page_attributes.fetch(:location)
          end
        end

        it 'should include :mtime' do
          with_info do |info|
            expect(info[:mtime]).to eq web_page_attributes.fetch(:mtime)
          end
        end
      end
    end

    context 'with required attributes' do
      let(:element) do
        Nokogiri::XML(document.source).elements.first
      end

      let(:source) do
        xml.web_page do
          xml.body(
              web_page_attributes.fetch(:body)
          )
          xml.code(
              web_page_attributes.fetch(:code)
          )

          serialized_headers = serialize(
              web_page_attributes.fetch(:headers)
          )
          xml.headers(serialized_headers)

          xml.host(
              host_attributes.fetch(:address)
          )
          xml.path(
              web_page_attributes.fetch(:headers)
          )
          xml.port(
              service_attributes.fetch(:port)
          )
          xml.query(
              web_page_attributes.fetch(:query)
          )

          ssl = false

          if service_attributes[:name] == 'https'
            ssl = true
          end

          xml.ssl(ssl)
        end

        xml.target!
      end

      it 'should create an Mdm::WebPage' do
        expect {
          import_msf_web_page_element
        }.to change(Mdm::WebPage, :count).by(1)
      end
    end
  end

  context '#import_msf_web_vuln_element' do
    let(:type) do
      :vuln
    end

    let(:web_vuln_attributes) do
      FactoryBot.attributes_for(:exported_web_vuln)
    end

    subject(:import_msf_web_vuln_element) do
      db_manager.import_msf_web_vuln_element(
          element,
          options,
          &notifier
      )
    end

    context 'call to #import_msf_web_element' do
      it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::XML#import_msf_web_element specialization'

      context 'specialization return' do
        let(:element) do
          Nokogiri::XML(document.source).elements.first
        end

        let(:source) do
          xml.web_vuln do
            xml.blame(
                web_vuln_attributes.fetch(:blame)
            )
            xml.category(
                web_vuln_attributes.fetch(:category)
            )
            xml.confidence(
                web_vuln_attributes.fetch(:confidence)
            )
            xml.description(
                web_vuln_attributes.fetch(:description)
            )
            xml.method(
                web_vuln_attributes.fetch(:method)
            )
            xml.name(
                web_vuln_attributes.fetch(:name)
            )
            xml.pname(
                web_vuln_attributes.fetch(:pname)
            )
            xml.proof(
                web_vuln_attributes.fetch(:proof)
            )
            xml.risk(
                web_vuln_attributes.fetch(:risk)
            )
          end

          xml.target!
        end

        it 'should be a Hash' do
          with_info do |info|
            expect(info).to be_a Hash
          end

          import_msf_web_vuln_element
        end

        it 'should include :blame' do
          with_info do |info|
            expect(info[:blame]).to eq web_vuln_attributes.fetch(:blame)
          end
        end

        it 'should include :category' do
          with_info do |info|
            expect(info[:category]).to eq web_vuln_attributes.fetch(:category)
          end
        end

        it 'should include :confidence' do
          with_info do |info|
            expect(info[:confidence]).to eq web_vuln_attributes.fetch(:confidence)
          end
        end

        it 'should include :description' do
          with_info do |info|
            expect(info[:description]).to eq web_vuln_attributes.fetch(:description)
          end
        end

        it 'should include :method' do
          with_info do |info|
            expect(info[:method]).to eq web_vuln_attributes.fetch(:method)
          end
        end

        it 'should include :name' do
          with_info do |info|
            expect(info[:name]).to eq web_vuln_attributes.fetch(:name)
          end
        end

        it 'should include :pname' do
          with_info do |info|
            expect(info[:pname]).to eq web_vuln_attributes.fetch(:pname)
          end
        end

        it 'should include :proof' do
          with_info do |info|
            expect(info[:proof]).to eq web_vuln_attributes.fetch(:proof)
          end
        end

        it 'should include :risk' do
          with_info do |info|
            expect(info[:risk]).to eq web_vuln_attributes.fetch(:risk)
          end
        end
      end
    end

    context 'with required attributes' do
      let(:element) do
        Nokogiri::XML(document.source).elements.first
      end

      let(:source) do
        xml.web_vuln do
          xml.category(
              web_vuln_attributes.fetch(:category)
          )
          xml.host(
              host_attributes.fetch(:address)
          )
          xml.method(
              web_vuln_attributes.fetch(:method)
          )
          xml.name(
              web_vuln_attributes.fetch(:name)
          )

          serialized_params = serialize(
              web_vuln_attributes.fetch(:params)
          )
          xml.params(serialized_params)

          xml.path(
              web_vuln_attributes.fetch(:path)
          )
          xml.pname(
              web_vuln_attributes.fetch(:pname)
          )
          xml.port(
              service_attributes.fetch(:port)
          )
          xml.proof(
              web_vuln_attributes.fetch(:proof)
          )
          xml.risk(
              web_vuln_attributes.fetch(:risk)
          )

          ssl = false

          if service_attributes[:name] == 'https'
            ssl = true
          end

          xml.ssl(ssl)
        end

        xml.target!
      end

      it 'should create an Mdm::WebVuln' do
        expect {
          import_msf_web_vuln_element
        }.to change(Mdm::WebVuln, :count).by(1)
      end
    end
  end

  context '#import_msf_xml' do
    let(:data) do
      '<MetasploitV4/>'
    end

    subject(:import_msf_xml) do
      db_manager.import_msf_xml(:data => data)
    end

    it 'should call #check_msf_xml_version!' do
      expect(db_manager).to receive(:check_msf_xml_version!).and_call_original

      import_msf_xml
    end

    context 'with web_forms/web_form elements' do
      let(:data) do
        xml.tag!('MetasploitV4') do
          xml.web_forms do
            xml.web_form do
              xml.host(
                  host_attributes.fetch(:address)
              )
              xml.method(
                  web_form_attributes.fetch(:method)
              )
              xml.path(
                  web_form_attributes.fetch(:path)
              )
              xml.port(
                  service_attributes.fetch(:port)
              )

              ssl = false

              if service_attributes[:name] == 'https'
                ssl = true
              end

              xml.ssl(ssl)
            end
          end
        end

        xml.target!
      end

      it 'should call #import_msf_web_form_element' do
        expect(db_manager).to receive(:import_msf_web_form_element).and_call_original

        import_msf_xml
      end
    end

    context 'with web_pages/web_page elements' do
      let(:data) do
        xml.tag!('MetasploitV4') do
          xml.web_pages do
            xml.web_page do
              xml.body(
                  web_page_attributes.fetch(:body)
              )
              xml.code(
                  web_page_attributes.fetch(:code)
              )

              serialized_headers = serialize(
                  web_page_attributes.fetch(:headers)
              )
              xml.headers(serialized_headers)

              xml.host(
                  host_attributes.fetch(:address)
              )
              xml.path(
                  web_page_attributes.fetch(:headers)
              )
              xml.port(
                  service_attributes.fetch(:port)
              )
              xml.query(
                  web_page_attributes.fetch(:query)
              )

              ssl = false

              if service_attributes[:name] == 'https'
                ssl = true
              end

              xml.ssl(ssl)
            end
          end
        end

        xml.target!
      end

      it 'should call #import_msf_web_page_element' do
        expect(db_manager).to receive(:import_msf_web_page_element).and_call_original

        import_msf_xml
      end
    end

    context 'with web_vulns/web_vuln elements' do
      let(:data) do
        xml.tag!('MetasploitV4') do
          xml.web_vulns do
            xml.web_vuln do
              xml.category(web_vuln.category)

              service = web_vuln.web_site.service
              xml.host(service.host.address)

              xml.method(web_vuln.method)
              xml.name(web_vuln.name)

              serialized_params = serialize(web_vuln.params)
              xml.params(serialized_params)

              xml.path(web_vuln.path)
              xml.pname(web_vuln.pname)
              xml.port(service.port)
              xml.proof(web_vuln.proof)

              ssl = false

              if service.name == 'https'
                ssl = true
              end

              xml.ssl(ssl)
            end
          end
        end

        xml.target!
      end

      let(:web_vuln) do
        FactoryBot.create(:mdm_web_vuln)
      end

      it 'should call #import_msf_web_vuln_element' do
        expect(db_manager).to receive(:import_msf_web_vuln_element).and_call_original

        import_msf_xml
      end
    end
  end
end
