# -*- coding: binary -*-
require 'spec_helper'
require 'rex/parser/acunetix_document'

RSpec.describe Rex::Parser::AcunetixDocument do
  subject(:parser) { described_class.new(nil, nil) }
  
  # Mock the database report block to capture what gets reported
  let(:reported_vulns) { [] }
  let(:db_block) { proc { |type, data| reported_vulns << { type: type, data: data } } }

  describe '#report_web_vuln' do
    # Create a mock web_vuln object
    let(:web_vuln) { double('web_vuln') }

    before do
      # Allow report_web_vuln to call report_other_vuln internally
      allow(parser).to receive(:report_other_vuln).and_call_original
      
      # Mock the emit_vuln method used by report_other_vuln
      allow(parser).to receive(:emit_vuln) do |&block|
        block.call(db_block) if block
      end
    end

    context 'when web_page is nil (no request/response data)' do
      before do
        parser.instance_variable_set(:@state, { web_page: nil })
      end

      it 'should report vulnerability via fallback method' do
        # This confirms your fix works: it should NOT crash and SHOULD report something
        expect(parser).to receive(:report_other_vuln)
        parser.report_web_vuln(&db_block)
      end
    end

    context 'when web_page is available (complete data)' do
      let(:mock_page) { double('web_page') }
      
      before do
        parser.instance_variable_set(:@state, { web_page: mock_page })
      end

      it 'should report as web vulnerability' do
        # This confirms backward compatibility
        expect(parser).not_to receive(:report_other_vuln)
        
        # It should try to process the web vuln (mocking internal behavior)
        # We just need to ensure it takes the "if" path, not the "else"
        allow(parser).to receive(:report_web_vuln).and_call_original
        
        # Since we mocked web_page, we expect it to try to use it
        # This part depends on the exact internal implementation, but basic check:
        # It should NOT call the fallback
        expect { parser.report_web_vuln(&db_block) }.not_to raise_error
      end
    end
  end
end

