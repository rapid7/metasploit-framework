# -*- coding: binary -*-

module Rex
module Exploitation
module Powershell
  ##
  # Convenience methods for generating powershell code in Ruby
  ##

  module PshMethods
    #
    # Download file via .NET WebClient
    #
    # @param src [String] URL to the file
    # @param target [String] Location to save the file
    #
    # @return [String] Powershell code to download a file
    def self.download(src, target)
      target ||= '$pwd\\' << src.split('/').last
      %Q^(new-object System.Net.WebClient).DownloadFile("#{src}", "#{target}")^
    end

    #
    # Uninstall app, or anything named like app
    #
    # @param app [String] Name of application
    # @param fuzzy [Boolean] Whether to apply a fuzzy match (-like) to
    #   the application name
    #
    # @return [String] Powershell code to uninstall an application
    def self.uninstall(app, fuzzy = true)
      match = fuzzy ? '-like' : '-eq'
      %Q^$app = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name #{match} "#{app}" }; $app.Uninstall()^
    end

    #
    # Create secure string from plaintext
    #
    # @param str [String] String to create as a SecureString
    #
    # @return [String] Powershell code to create a SecureString
    def self.secure_string(str)
      %Q(ConvertTo-SecureString -string '#{str}' -AsPlainText -Force$)
    end

    #
    # Find PID of file lock owner
    #
    # @param filename [String] Filename
    #
    # @return [String] Powershell code to identify the PID of a file
    #   lock owner
    def self.who_locked_file(filename)
      %Q^ Get-Process | foreach{$processVar = $_;$_.Modules | foreach{if($_.FileName -eq "#{filename}"){$processVar.Name + " PID:" + $processVar.id}}}^
    end

    #
    # Return last time of login
    #
    # @param user [String] Username
    #
    # @return [String] Powershell code to return the last time of a user
    #   login
    def self.get_last_login(user)
      %Q^ Get-QADComputer -ComputerRole DomainController | foreach { (Get-QADUser -Service $_.Name -SamAccountName "#{user}").LastLogon} | Measure-Latest^
    end
  end
end
end
end
