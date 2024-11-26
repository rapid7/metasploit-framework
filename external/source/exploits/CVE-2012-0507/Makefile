JAR = CVE-2012-0507.jar

CLASSES = \
	msf/x/Exploit.java  \
	msf/x/Help.java     \
	msf/x/PayloadX.java 


.SUFFIXES: .java .class
.java.class:
	javac -d bin -source 1.2 -target 1.2 $*.java

all: $(CLASSES:.java=.class)
	(cd bin; jar cvf ../$(JAR) *)

install:
	mv $(JAR) ../../../../data/exploits/

clean:
	rm -f $(JAR)
	rm -rf bin/*


