<html><head>
<meta http-equiv="content-type" content="text/html; charset=windows-1252">

</head>
<body onload="initDoc()">

<div id="overview_info">
<h2>Windows Gather MDaemonEmailServer Credential Cracking</h2><hr>
<p>
Finds and cracks the stored passwords of MDaemon Email 
Server.

</p>
<h2>Module Name</h2><hr>
<p>post/windows/gather/credentials/mdaemon_cred_collector</p>
<h2>Authors</h2><hr><ul><li>Manuel Nader @AgoraSecurity</li>
</ul><h2>Required Options</h2><hr><ul><li>SESSION - The session to run this module on.</li>
</ul><h2>Vulnerable Applications</h2><hr>
<ul><li>MDaemon e-Mail Server Software for Windows</li>
</ul><h2>Platforms</h2><hr><ul><li>win</li>
</ul><h2>Reliability</h2><hr>
<p><a href="https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking">Excellent</a></p>
<h2>References</h2><hr><ul>
<li><a href="http://www.securityfocus.com/bid/4686">http://www.securityfocus.com/bid/4686</a></li>
<li><a href="https://github.com/AgoraSecurity/MdaemonCrack">https://github.com/AgoraSecurity/MdaemonCrack</a></li>
</ul><h2>Required Options</h2><hr><ul><li>SESSION - The session to run this module on.</li>
</ul><h2>Options</h2><hr><ul>
<li>RPATH - The remote path of the MDaemon installation.</li>
<li>Verbose - Will display more information of the module while running.</li>
</ul><h2>Verification Steps</h2><hr>
<p>1 - Get a meterpreter on a windows machine that has MDaemon installed.</p>

<p>2 - Load the module:</p>
<pre><code>msf &gt; use post/windows/gather/credentials/mdaemon_cred_collector</code></pre>

<p>3 - Set the correct session on the module. Optional: you can add the remote path of the installation, especially if the software is installed on a strange path and the module can't find it..</p>

<p>4 - Run the module and enjoy the loot.</p>


</ul><h2>Basic Usage</h2><hr>
<p><strong>From the msf prompt</strong></p>

<p>By using the "use" command at the msf prompt. You will have to figure out which
session ID to set manually. To list all session IDs, you can use the "sessions" command.</p>
<pre><code>msf &gt; use post/windows/gather/credentials/mdaemon_cred_collector
msf post(mdaemon_cred_collector) &gt; show options
    ... show and set options ...
msf post(mdaemon_cred_collector) &gt; set SESSION session-id
msf post(mdaemon_cred_collector) &gt; exploit
</code></pre>
<p>If you wish to run the post against all sessions from framework, here is how:</p>

<p>1 - Create the following resource script:</p>
<pre><code><ruby>
framework.sessions.each_pair do |sid, session|
  run_single("use post/windows/gather/credentials/mdaemon_cred_collector")
  run_single("set SESSION #{sid}")
  run_single("run")
end
</ruby>
</code></pre>
<p>2 - At the msf prompt, execute the above resource script:</p>
<pre><code>msf &gt; resource path-to-resource-script
</code></pre>

</ul><h2>Scenarios</h2><hr>
<p><strong>Meterpreter on email server</strong></p>

<p>If you have a meterpreter running on a server that has MDaemon installed, run the module and you will get all the users and passwords of the email server. Quite useful for trying password reuse and/or checking the strength of the passwords.</p>

<p>Note: MDaemon can store the passwords on a database, in that case the module won't work, but you can search for the database location, username and password and still get them :)</p>

</div>


</body></html>
