#This is the step definition file for common framework testing steps or meta steps

When /^I run the "([^"]*)" exploit with standard target options$/ do |exploit|
  steps %Q{
    When I run `#{exploit} RHOST=#{TestConfig.instance.rhost} SMBPass=#{TestConfig.instance.smbpass} SMBUser=#{TestConfig.instance.smbuser} E` interactively
  }
  end

When /^I run the "([^"]*)" exploit with standard target options in check mode$/ do |exploit|
  steps %Q{
    When I run `#{exploit} RHOST=#{TestConfig.instance.rhost} SMBPass=#{TestConfig.instance.smbpass} SMBUser=#{TestConfig.instance.smbuser} C` interactively
  }
  end

When /^I run msfvenom to encode for windows using the "([^"]*)" encoder with "(.*)" options$/ do |encoder, options|
  steps %Q{
    When I run `./msfvenom ./msfvenom -p windows/shell/bind_tcp -e #{encoder} #{options}` interactively
  }
  end

When /^I run msfvenom to encode for windows using the "([^"]*)" encoder with "(.*)" options and a buffer register$/ do |encoder, options|
  steps %Q{
    When I run `./msfvenom ./msfvenom -p windows/shell/bind_tcp -e #{encoder} #{options} BufferRegister=eax` interactively
  }
  end

When /^I run msfpayload to generate a "([^"]*)" on the local host$/ do |payload|
  steps %Q{
      When I run `./msfpayload #{payload} LHOST=127.0.0.1 y`
  }
  end