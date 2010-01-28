#!/usr/bin/ruby

require 'rubygems'
require 'rjb'

Rjb::load(ENV['JAVA_HOME'] + '/lib/tools.jar:.',jvmargs=[])

# This is a completely hackish way to do this, and could break with future
# versions of the JDK.  Need to find a better way to use sun.security.tools.KeyTool
# and .JarSigner than modifying the source.  These rely on internal APIs that may
# change.
signer = Rjb::import('javaCompile.SignJar')
#clsKeyTool = Rjb::import('sun.security.tools.KeyTool')
#clsKeyTool = Rjb::import('sun.security.tools.KeyToolMSF')
#clsJarSigner = Rjb::import('javaCompile.SignJar.JarSignerMSF')
#clsJarSigner = Rjb::import('sun.security.tools.JarSigner')
#clsJarSigner = Rjb::import('sun.security.tools.JarSignerMSF')

#keytool = clsKeyTool
#jarsigner = clsJarSigner

outputJar = "output.jar"

#certCN cannot contain commas
certCN 		= "Metasploit Inc."
#keytoolOpts 	= "-genkey -alias signFiles -keystore msfkeystore " +
#		  "-storepass msfstorepass -dname \"cn=#{certCN}\" " +
#		  "-keypass msfkeypass"

keytoolOpts 	= ["-genkey", "-alias", "signFiles", "-keystore", "msfkeystore",
		   "-storepass", "msfstorepass", "-dname", "cn=#{certCN}",
		   "-keypass", "msfkeypass"]


signer._invoke('KeyToolMSF','[Ljava.lang.String;',keytoolOpts)


jarsignerOpts	= ["-keystore", "msfkeystore", "-storepass", "msfstorepass",
		   "-keypass", "msfkeypass", "-signedJar", "s#{outputJar}",
		   outputJar, "signFiles"]

signer._invoke('JarSignerMSF','[Ljava.lang.String;',jarsignerOpts)


