module Msf
module Ui
module Web

###
#
# This class implements helper methods for sharing across web pages.
#
###
module Common

	#
	# Returns the header string that is common to most pages.
	#
	def self.header(v, active = "none")
		"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">
<html>
	<head>
		<title>Metasploit Framework Web Console v#{v}</title>
		<link type='text/css' rel='stylesheet' href='style.css'/>
	</head>
	<body>
		<br/>
		
		<div align='center'>
			<img src='images/logo.jpg' alt='msfweb'/>
		</div>

		<table align='center' cellpadding='8' border='0' cellspacing='1' width='100%' class='tblInner'>
			<tr>
				<td>
					<table align='center' cellpadding='8' cellspacing='1' width='100%' class='tblOuter'>
						<tr>
							<td class='tab" + ((active == "exploits") ? "Light" : "Dark") + "' width='33%' align='center'>
								<a href='exploits.rhtml'>EXPLOITS</a>
							</td>
							<td class='tab" + ((active == "payloads") ? "Light" : "Dark") + "' width='33%' align='center'>
								<a href='payloads.rhtml'>PAYLOADS</a>
							</td>
							<td class='tab" + ((active == "sessions") ? "Light" : "Dark") + "' width='33%' align='center'>
								<a href='sessions.rhtml'>SESSIONS</a>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
		"
	end

	def self.footer
		"
		<br/>
	</body>
</html>
		"
	end

end

end
end
end
