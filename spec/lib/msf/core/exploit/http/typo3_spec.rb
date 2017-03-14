# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'rex/proto/http/response'
require 'msf/core/exploit/http/typo3'

RSpec.describe Msf::Exploit::Remote::HTTP::Typo3 do
  subject do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  let(:invalid_user) do
    "invalid"
  end

  let(:invalid_password) do
    "invalid"
  end

  let(:valid_user) do
    "admin"
  end

  let(:valid_password) do
    "password"
  end

  let(:valid_cookie) do
    "be_typo_user=e31843639e5e17b9600602f9378b6ff0"
  end

  describe '#target_uri' do
    it 'returns an URI' do
      expect(subject.target_uri).to be_kind_of URI
    end
  end

  describe '#typo3_url_login' do
    it 'ends with /typo3/index.php' do
      expect(subject.typo3_url_login).to end_with('/typo3/index.php')
    end
  end

  describe '#typo3_url_backend' do
    it 'ends with /typo3/backend.php' do
      expect(subject.typo3_url_backend).to end_with('/typo3/backend.php')
    end
  end

  describe '#typo3_admin_cookie_valid?' do
    it 'returns true when valid admin cookie' do
      allow(subject).to receive(:send_request_cgi) do
        res = Rex::Proto::Http::Response.new
        res.body = '<body class="test" id="typo3-backend-php">'
        res
      end

      expect(subject.typo3_admin_cookie_valid?("#{valid_cookie};")).to eq(true)
    end

    it 'returns false when invalid admin cookie' do
      allow(subject).to receive(:send_request_cgi) do
        res = Rex::Proto::Http::Response.new
        res
      end

      expect(subject.typo3_admin_cookie_valid?("invalid")).to eq(false)
    end
  end

  describe '#typo3_backend_login' do

    it 'returns nil login page can not be reached' do
      allow(subject).to receive(:send_request_cgi) do
        res = Rex::Proto::Http::Response::E404.new
        res
      end

      expect(subject.typo3_backend_login(valid_user, valid_password)).to be_nil
    end

    it 'returns nil when login page can be reached but isn\'t a TYPO3' do
      allow(subject).to receive(:send_request_cgi) do
        res = Rex::Proto::Http::Response.new
        res.body = 'Hello World'
        res
      end

      expect(subject.typo3_backend_login(valid_user, valid_password)).to be_nil
    end

    it 'returns nil when TYPO3 credentials are invalid' do

      allow(subject).to receive(:send_request_cgi) do |opts|
        if opts['uri'] == "/typo3/index.php" && opts['method'] == 'GET'
          res = Rex::Proto::Http::Response.new
          res.body = '<input type="hidden" id="rsa_e" name="e" value="10001" />'
          res.body << '<input type="hidden" id="rsa_n" name="n" value="B8C58D75B5F9DBCEBBF6FB96BDB9531C64C45DDED56D93B310FA9C79B9787E62C91157DD5842B2BC1D90C10251300571BEEF892776F25EAC80C2672A993B00DA2F1C966C3F70418274E1AC9C432F48F8CBD9D083F990905F7EC5BDFC1B5C93672E7ACBB3D935D0597864A1F732DD44B5C6E02344917543E33A36D68915B26DC9" />'
        elsif opts['uri'] == "/typo3/index.php" && opts['method'] == 'POST'
          res = Rex::Proto::Http::Response.new
          res.body = '<!-- ###LOGIN_ERROR### begin -->Login Failed<!-- ###LOGIN_ERROR### end -->'
        else
          res = Rex::Proto::Http::Response::E404.new
        end

        res
      end

      expect(subject.typo3_backend_login(invalid_user, invalid_password)).to be_nil
    end

    it 'returns a cookie string when TYPO3 credentials are valid' do
      allow(subject).to receive(:send_request_cgi) do |opts|
        if opts['uri'] == "/typo3/index.php" && opts['method'] == 'GET'
          res = Rex::Proto::Http::Response.new
          res.body = '<input type="hidden" id="rsa_e" name="e" value="10001" />'
          res.body << '<input type="hidden" id="rsa_n" name="n" value="B8C58D75B5F9DBCEBBF6FB96BDB9531C64C45DDED56D93B310FA9C79B9787E62C91157DD5842B2BC1D90C10251300571BEEF892776F25EAC80C2672A993B00DA2F1C966C3F70418274E1AC9C432F48F8CBD9D083F990905F7EC5BDFC1B5C93672E7ACBB3D935D0597864A1F732DD44B5C6E02344917543E33A36D68915B26DC9" />'
        elsif opts['uri'] == "/typo3/index.php" && opts['method'] == 'POST'
          res = Rex::Proto::Http::Response.new
          res.headers['Set-Cookie'] = "#{valid_cookie};"
        elsif opts['uri'] == "/typo3/backend.php" && opts['method'] == 'GET'
          res = Rex::Proto::Http::Response.new
          res.body = '<body class="test" id="typo3-backend-php">'
          res
        else
          res = Rex::Proto::Http::Response::E404.new
        end

        res
      end

      expect(subject.typo3_backend_login(valid_user, valid_password)).to include(valid_cookie)
    end
  end

end
