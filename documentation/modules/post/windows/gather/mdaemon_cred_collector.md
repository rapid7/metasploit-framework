<html><head>
<meta http-equiv="content-type" content="text/html; charset=windows-1252">

<style>
h1, h2, h3, h4, h5, h6, p, blockquote {
    margin: 0;
    padding: 0;
}
body {
    font-family: Arial, "Helvetica Neue", Helvetica, "Hiragino Sans GB", sans-serif;
    font-size: 16px;
    line-height: 18px;
    color: #737373;
    margin: 10px 13px 10px 13px;
}
a {
    color: #0069d6;
}
a:hover {
    color: #0050a3;
    text-decoration: none;
}
a img {
    border: none;
}
p {
    margin-bottom: 16px;
}
h1, h2, h3, h4, h5, h6 {
    color: #404040;
    line-height: 36px;
}
h1 {
    margin-bottom: 18px;
    font-size: 30px;
}
h2 {
    font-size: 24px;
    margin-bottom: 16px;
}
h3 {
    font-size: 18px;
    margin-bottom: 16px;
}
h4 {
    font-size: 16px;
    margin-bottom: 16px;
}
h5 {
    font-size: 16px;
    margin-bottom: 16px;
}
h6 {
    font-size: 13px;
    margin-bottom: 16px;
}
hr {
    margin: 0 0 19px;
    border: 0;
    border-bottom: 1px solid #eee;
}
blockquote {
    padding: 13px 13px 21px 15px;
    margin-bottom: 18px;
    font-family:georgia,serif;
    font-style: italic;
}
blockquote:before {
    content:"\201C";
    font-size:40px;
    margin-left:-10px;
    font-family:georgia,serif;
    color:#eee;
}
blockquote p {
    font-size: 16px;
    font-weight: 300;
    line-height: 18px;
    margin-bottom: 0;
    font-style: italic;
}
code, pre {
    font-family: Monaco, Andale Mono, Courier New, monospace;
}
code {
    background-color: #eee;
    color: rgba(0, 0, 0, 0.75);
    padding: 1px 3px;
    font-size: 13px;
    -webkit-border-radius: 3px;
    -moz-border-radius: 3px;
    border-radius: 3px;
}
pre {
    display: block;
    margin: 0 0 18px;
    line-height: 16px;
    font-size: 13px;
    border: 1px solid #d9d9d9;
    white-space: pre-wrap;
    word-wrap: break-word;
}
pre code {
    background-color: #fff;
    color:#737373;
    font-size: 13px;
    padding: 0;
}
@media screen and (min-width: 768px) {
    body {
        width: 748px;
        margin:10px auto;
    }
}
#overview_info_button {
  font-family:Arial, sans-serif;
  font-size:16px;
  padding:10px 5px;
  border-style:solid;
  border-width:1px;
  border-color:#EEEEEE;
  color:#C4C4C4;
}
#knowledge_base_button {
  font-family:Arial, sans-serif;
  font-size:16px;
  padding:10px 5px;
  border-style:solid;
  border-width:1px;
  border-color:#ccc;
  color:#333;
}
#overview_info_button:hover, #knowledge_base_button:hover {
  cursor: pointer;
}
#long_list {
  height:280px;
  overflow:auto;
  border-style: solid;
  border-width: 1px;
  border-color: #ccc;
}


/*
Description: Foundation 4 docs style for highlight.js
Author: Dan Allen <dan.j.allen@gmail.com>
Website: http://foundation.zurb.com/docs/
Version: 1.0
Date: 2013-04-02
*/

pre code {
  display: block; padding: 0.5em;
  background: #eee;
}

pre .decorator,
pre .annotation {
  color: #000077;
}

pre .attribute {
  color: #070;
}

pre .value,
pre .string,
pre .scss .value .string {
  color: #d14;
}

pre .comment {
  color: #998;
  font-style: italic;
}

pre .function .title {
  color: #900;
}

pre .class {
  color: #458;
}

pre .id,
pre .pseudo,
pre .constant,
pre .hexcolor {
  color: teal;
}

pre .variable {
  color: #336699;
}

pre .javadoc {
  color: #997700;
}

pre .pi,
pre .doctype {
  color: #3344bb;
}

pre .number {
  color: #099;
}

pre .important {
  color: #f00;
}

pre .label {
  color: #970;
}

pre .preprocessor {
  color: #579;
}

pre .reserved,
pre .keyword,
pre .scss .value {
  color: #000;
}

pre .regexp {
  background-color: #fff0ff;
  color: #880088;
}

pre .symbol {
  color: #990073;
}

pre .symbol .string {
  color: #a60;
}

pre .tag {
  color: #007700;
}

pre .at_rule,
pre .at_rule .keyword {
  color: #088;
}

pre .at_rule .preprocessor {
  color: #808;
}

pre .scss .tag,
pre .scss .attribute {
  color: #339;
}
</style>
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
