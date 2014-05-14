
require 'spec_helper'
require 'metasploit/framework/login_scanner/http'

describe Metasploit::Framework::LoginScanner::HTTP do

  subject(:http_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  it { should respond_to :uri }
  it { should respond_to :method }

  context "#set_sane_defaults" do

    context "without ssl, without port" do
      it "should default :port to #{described_class::DEFAULT_PORT}" do
        expect(http_scanner.ssl).to be_false
        expect(http_scanner.port).to eq(described_class::DEFAULT_PORT)
      end
    end

    context "with ssl, without port" do
      subject(:http_scanner) { described_class.new(ssl:true) }
      it "should set :port to default ssl port (#{described_class::DEFAULT_SSL_PORT})" do
        expect(http_scanner.ssl).to be_true
        expect(http_scanner.port).to eq(described_class::DEFAULT_SSL_PORT)
      end
    end

    context "without ssl, with default port" do
      subject(:http_scanner) { described_class.new(port:described_class::DEFAULT_PORT) }
      it "should set ssl to false" do
        expect(http_scanner.port).to eq(described_class::DEFAULT_PORT)
        expect(http_scanner.ssl).to be_false
      end
    end

    context "without ssl, with default SSL port" do
      subject(:http_scanner) { described_class.new(port:described_class::DEFAULT_SSL_PORT) }
      it "should set ssl to true" do
        expect(http_scanner.ssl).to be_true
        expect(http_scanner.port).to eq(described_class::DEFAULT_SSL_PORT)
      end
    end

    context "without ssl, with non-default port" do
      subject(:http_scanner) { described_class.new(port:0) }
      it "should not set ssl" do
        expect(http_scanner.ssl).to be_nil
        expect(http_scanner.port).to eq(0)
      end
    end

  end
end
