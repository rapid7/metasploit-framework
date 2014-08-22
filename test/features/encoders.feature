#This feature contains scenarios that test the various encoders within the metasploit framework

@announce-stdout

Feature: As a Metasploit Framework user
	I want to user encoders
	So that I can encode various payloads I might use for attacks

Scenario: Create a windows tcp bind payload using the x86/unicode mixed encoder
		When I run msfvenom to encode for windows using the "x86/unicode_mixed" encoder with "-i 1" options and a buffer register
        #When I run `./msfvenom -p windows/shell/bind_tcp -e x86/unicode_mixed -i 1 BufferRegister=eax` interactively
        Then the output should contain "x86/unicode_mixed succeeded with size"

Scenario: Create a windows tcp bind payload encoded with x86 alpha mixed
	When I run msfvenom to encode for windows using the "x86/alpha_mixed" encoder with "-b '\x00' -i 1" options
	#When I run `./msfvenom -p windows/shell/bind_tcp -e x86/alpha_mixed -b '\x00' -i 1` interactively
	Then the output should contain "x86/alpha_mixed succeeded with size"

