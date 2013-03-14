JAR = CVE-2012-1723.jar

ASM = asm-4.0.jar
LIB = lib
BIN = bin
SRC = src

JAVAC = javac -source 1.5 -target 1.5

all:
	${JAVAC} -cp ${LIB}/${ASM} src/cve1723/Generator.java -d ${LIB}
	java -cp ${LIB}:${LIB}/${ASM} cve1723.Generator
	-mkdir ${BIN}
	-mkdir ${BIN}/cve1723/
	mv Confuser.class ${BIN}/cve1723/
	find ${SRC} -not -name 'Generator.java' -name '*.java' -type f -print0 | xargs -0 ${JAVAC} -cp ${BIN} -sourcepath {} -d ${BIN}
	jar cf ${JAR} -C ${BIN} .

install: ${JAR}
	cp ${JAR} ../../../../data/exploits

clean:
	rm -rf ${BIN}
	-rm ${LIB}/cve1723/Generator.class
	-rm ${JAR}
