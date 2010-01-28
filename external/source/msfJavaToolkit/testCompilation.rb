#!/usr/bin/ruby

require 'rubygems'
require 'rjb'

#Rjb::load('.', jvmargs=[])
Rjb::load("#{ENV['JAVA_HOME']}/lib/tools.jar:.",jvmargs=[])

clsJavaCompile 	= Rjb::import('javaCompile.CompileSourceInMemory')
clsCreateJar	= Rjb::import('javaCompile.CreateJarFile')
clsFile			= Rjb::import('java.io.File')
system			= Rjb::import('java.lang.System')
#clsString	= Rjb::import('java.lang.String')

classNames = [ "HelloWorld1", "HelloWorld2" ]

codez = Array.new

classNames.each { |name|
	codez << %Q^
public class #{name} {
	public static void main(String args[]) {
		System.out.println("This is from #{name}.");
	}
}^}

#compileOpts = [""]
#outputDir		= system.getProperty('java.io.tmpdir')
outputDir		= "testoutdir"
compileOpts 	= [ "-target", "1.3", "-source", "1.3", "-d", outputDir ]

success = clsJavaCompile._invoke('CompileFromMemory','[Ljava.lang.String;[Ljava.lang.String;[Ljava.lang.String;', classNames, codez, compileOpts)

fileOutJar 	= clsFile.new_with_sig('Ljava.lang.String;', 'output.jar')
filesIn		= Array.new

classNames.each { |name|
	filesIn << clsFile.new_with_sig('Ljava.lang.String;', "#{outputDir}/#{name}.class")
}

clsCreateJar._invoke('createJarArchive', 'Ljava.io.File;[Ljava.io.File;', fileOutJar, filesIn)

