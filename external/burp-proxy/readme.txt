=[Burp proxy WMAP Plugin				                     spinbad.security@googlemail.com 
------------------------------------------------------------------------------------------------------------


=[ Intro.
	
Simple plugin for the burp proxy 1.1/1.2 which stores the requests
in the metasploit/wmap database. At the moment only
sqlite3 is supported, I will add support for other databases
in later releases...


=[ Howto install/run.

1. Download burp proxy 1.2: http://portswigger.net/suite/burpsuite_v1.2.zip
2. Download SQLiteJDBC Jar: http://www.zentus.com/sqlitejdbc/
3. Copy sqlitejdbc-v054.jar and wmapplugin.jar into the burp proxy directory 
4. Run the following command:

   java -cp sqlitejdbc-v054.jar;burpsuite_v1.2.jar;wmap_plugin_v0.1-burp_v1.2.jar burp.StartBurp database=test.db   

   test.db is the name/path of your metasploit sqlite3 database file. You must create the db schema
   in the metasploit framework first (by using "db_create")   
	

=[ Questions/Answers


1. Can I use the burp spider to fill my WMAP request table?

   Sorry, no you can't. The reason is that the spider doesn't call implementations of the IBurpExtender
   interface. So you can only use the MITM Proxy. 


2. I found a bug, what can I do?
  
   You can send a description to spinbad.security@googlemail.com. I will try to fix it.

3. Is there a way to extend the stuff you wrote?
   Shure, I included the source code in the jar file. Feel free to use it.      

=[ EOF. 