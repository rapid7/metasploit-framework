# -*- coding:binary -*-
require 'spec_helper'

require 'rex/powershell'

RSpec.describe Rex::Powershell::PshMethods do

  describe "::download" do
    it 'should return some powershell' do
      script = Rex::Powershell::PshMethods.download('a','b')
      expect(script).to be
      expect(script.include?('WebClient')).to be_truthy
    end
  end
  describe "::uninstall" do
    it 'should return some powershell' do
      script = Rex::Powershell::PshMethods.uninstall('a')
      expect(script).to be
      expect(script.include?('Win32_Product')).to be_truthy
    end
  end
  describe "::secure_string" do
    it 'should return some powershell' do
      script = Rex::Powershell::PshMethods.secure_string('a')
      expect(script).to be
      expect(script.include?('AsPlainText')).to be_truthy
    end
  end
  describe "::who_locked_file" do
    it 'should return some powershell' do
      script = Rex::Powershell::PshMethods.who_locked_file('a')
      expect(script).to be
      expect(script.include?('Get-Process')).to be_truthy
    end
  end
  describe "::get_last_login" do
    it 'should return some powershell' do
      script = Rex::Powershell::PshMethods.get_last_login('a')
      expect(script).to be
      expect(script.include?('Get-QADComputer')).to be_truthy
    end
  end
  describe "::proxy_aware_download_and_exec_string" do
    it 'should return some powershell' do
      url = 'http://blah'
      script = Rex::Powershell::PshMethods.proxy_aware_download_and_exec_string(url)
      expect(script).to be
      expect(script.include?(url)).to be_truthy
      expect(script.downcase.include?('downloadstring')).to be_truthy
    end
  end
end

