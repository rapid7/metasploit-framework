# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/powershell'

describe Rex::Exploitation::Powershell::PshMethods do

  describe "::download" do
    it 'should return some powershell' do
      script = Rex::Exploitation::Powershell::PshMethods.download('a','b')
      script.should be
      script.include?('WebClient').should be_true
    end
  end
  describe "::uninstall" do
    it 'should return some powershell' do
      script = Rex::Exploitation::Powershell::PshMethods.uninstall('a')
      script.should be
      script.include?('Win32_Product').should be_true
    end
  end
  describe "::secure_string" do
    it 'should return some powershell' do
      script = Rex::Exploitation::Powershell::PshMethods.secure_string('a')
      script.should be
      script.include?('AsPlainText').should be_true
    end
  end
  describe "::who_locked_file" do
    it 'should return some powershell' do
      script = Rex::Exploitation::Powershell::PshMethods.who_locked_file('a')
      script.should be
      script.include?('Get-Process').should be_true
    end
  end
  describe "::get_last_login" do
    it 'should return some powershell' do
      script = Rex::Exploitation::Powershell::PshMethods.get_last_login('a')
      script.should be
      script.include?('Get-QADComputer').should be_true
    end
  end
end

