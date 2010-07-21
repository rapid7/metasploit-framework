
CVE-2008-5353.jar: src/msf/x/AppletX.java src/msf/x/PayloadX.java src/msf/x/LoaderX.java 
	javac -d bin -source 1.4 src/msf/x/*.java && (cd bin; jar cvf ../CVE-2008-5353.jar msf/x/*.class)

all: CVE-2008-5353.jar

install: all
	mv CVE-2008-5353.jar ../../../../data/exploits/
