To compile JavaPayload for Metasploit (including Java Meterpreter), you need
Maven 3.0 or above. Just run

mvn package

to package all the files, or

mvn -P deploy package

to package all the files and copy them into the correct place for Metasploit
(/data/java). If you get spurious compilation errors, make sure that there
is an exclude rule in your antivirus for the Metasploit directory (or that
your antivirus is disabled).

In case you want to edit/debug JavaPayload for Metasploit or Java Meterpreter,
Maven provides plugins to auto-generate project files for your favourite IDE
(at least for Eclipse, Netbeans or IntelliJ). I use Eclipse, so to generate
project files I use

mvn eclipse:eclipse

This will generate project files that can be imported via 

File->Import->Existing Projects into Workspace

into your Eclipse workspace.

(Note that if this is your first Maven project you want to use in Eclipse, you
also have to run 

mvn -Declipse.workspace=/path/to/your/workspace eclipse:configure-workspace

to set up path variables like M2_REPO to point to the correct location.)

For NetBeans or IntelliJ IDEA, refer to the documentation at

http://maven.apache.org/netbeans-module.html
http://maven.apache.org/plugins/maven-idea-plugin/

