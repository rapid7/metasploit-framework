Instead of embedding static Java serialized objects, Metasploit offers ysoserial-generated binaries with built-in randomization.  The benefits of using the Metasploit library include quicker module development, easier-to-read code, and future-proof Java serialized objects.

To use the ysoserial libraries, let's look at an example from the [shiro_rememberme_v124_deserialize][2] module:

## Example code

In this example:
1. (L11) The module includes the `Msf::Exploit::JavaDeserialization` mixin.
    * This exposes the necessary methods.
1. (L79) Then it uses the `generate_java_deserialization_for_payload` method to create a serialized Java object based on the `CommonsCollections2` YSoSerial payload that will execute the Metasploit payload.
    * Note that the Metasploit `payload` object is passed as-is, without any conversion.

```
09  include Msf::Exploit::Remote::HttpClient
10  include Msf::Exploit::Powershell
11  include Msf::Exploit::JavaDeserialization
12
13  def initialize(info = {})
...
78  def exploit
79    java_payload = generate_java_deserialization_for_payload('CommonsCollections2', payload)
80    ciphertext = aes_encrypt(java_payload)
```

Once the serialized object is generated and stored as `java_payload`, it's then sent to the target in an exploit-specific manner.

## Methods

### `#generate_java_deserialization_for_payload(name, payload)`
This method will generate a serialized Java object that when loaded will execute the specified Metasploit payload. The payload will be converted to an operating system command using one of the supported techniques contained within this method and then passed to [`#generate_java_deserialization_for_command`](#generate_java_deserialization_for_commandname-shell-command).
 
- **name** - The payload name parameter must be one of the supported payloads stored in the `ysoserial` cache.  As of this writing, the list includes: `BeanShelll1`, `Clogure`, `CommonsBeanutils1`, `CommonsCollections2`, `CommonsCollections3`, `CommonsCollections4`, `CommonsCollections5`, `CommonsCollections6`, `Groovy1`, `Hibernate1`, `JBossInterceptors1`, `JRMPClient`, `JSON1`, `JavassistWeld1`, `Jdk7u21`, `MozillaRhino1`, `Myfaces1`, `ROME`, `Spring1`, `Spring2`, and `Vaadin1`.  While `ysoserial` includes additional payloads that are not listed above, they are unsupported by the library due to the need for complex inputs.  Should there be use cases for additional payloads, please consider opening an issue and submitting a pull request to add support.
 
- **payload** - The payload object to execute on the remote system. This is the native Metasploit payload object and it will be automatically converted to an operating system command using a technique suitable for the target platform and architecture. For example, x86 Windows payloads will be converted using a Powershell command. Not all platforms and architecture combinations are supported. Unsupported combinations will result in a `RuntimeError` being raised which will need to be handled by the module developer.

### `#generate_java_deserialization_for_command(name, shell, command)`
This method will generate a serialized Java object that when loaded will execute the specific operating system command using the specified shell. Invocation of the command through the shell effectively bypasses constraints on the characters within the operating system command.

- **name** - The payload name parameter. This has the same significance as the *name* parameter for the [`#generate_java_deserialization_for_payload`](#generate_java_deserialization_for_payloadname-payload) method.

- **shell** - The shell to use for invoking the command. This value must be one of the following:

    - **bash** - A modified version that will invoke the command using the `bash` executable
    - **cmd** - A modified version that will invoke the command using the Windows `cmd.exe` executable.
    - **powershell** - A modified version that will invoke the command using the Windows `powershell.exe` executable.

- **command** - The operating system command to execute upon successful deserialization of the generated object.

## Regenerating the ysoserial_payload JSON file (MAINTAINERS ONLY)

**Neither module developers nor users need to concern themselves with the following.**

On occasion, Metasploit maintainers may want to re-run the script generation to incorporate new Java serialized objects from the ysoserial tool.

To avoid invoking Java (and all its dependencies) at runtime, the serialized objects are generated and cached within a JSON file.  The JSON file can be refreshed using a standalone Ruby script, which comes prepackaged with a Docker image that handles downloading `ysoserial` and necessary dependencies.  The script, `Dockerimage` and a high-level `runme.sh` script is stored within `tools/payloads/ysoserial`.  An example run looks like:

```
$ cd ~/git/r7/metasploit-framework/tools/payloads/ysoserial
$ ./runme.sh 
Sending build context to Docker daemon  101.8MB
Step 1/8 : FROM ubuntu
 ---> cd6d8154f1e1
Step 2/8 : RUN apt update && apt -y upgrade
 ---> Using cache
 ---> ba7e5691ed5a
Step 3/8 : RUN apt install -y wget openjdk-8-jre-headless ruby-dev make gcc
 ---> Using cache
 ---> d38488663627
Step 4/8 : RUN wget -q https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O ysoserial-original.jar
 ---> Using cache
 ---> 284ff722464b
Step 5/8 : RUN wget -q https://github.com/pimps/ysoserial-modified/raw/master/target/ysoserial-modified.jar
 ---> Using cache
 ---> 334c1ccb6fab
Step 6/8 : RUN gem install --silent diff-lcs json pry
 ---> Using cache
 ---> 9d452be9d01f
Step 7/8 : COPY find_ysoserial_offsets.rb /
 ---> 61b6f339590c
Step 8/8 : CMD ruby /find_ysoserial_offsets.rb
 ---> Running in ba7b14646e56
Removing intermediate container ba7b14646e56
 ---> f4ca5ecb6848
Successfully built f4ca5ecb6848
Successfully tagged ysoserial-payloads:latest
Generating payloads for BeanShell1...
Generating payloads for C3P0...
    Error while generating or serializing payload
    java.lang.IllegalArgumentException: Command format is: <base_url>:<classname>
    	at ysoserial.payloads.C3P0.getObject(C3P0.java:48)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'C3P0' and it will not be supported
Generating payloads for Clojure...
Generating payloads for CommonsBeanutils1...
Generating payloads for CommonsCollections1...
Generating payloads for CommonsCollections2...
Generating payloads for CommonsCollections3...
Generating payloads for CommonsCollections4...
Generating payloads for CommonsCollections5...
Generating payloads for CommonsCollections6...
Generating payloads for FileUpload1...
    Error while generating or serializing payload
    java.lang.IllegalArgumentException: Unsupported command  []
    	at ysoserial.payloads.FileUpload1.getObject(FileUpload1.java:71)
    	at ysoserial.payloads.FileUpload1.getObject(FileUpload1.java:40)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'FileUpload1' and it will not be supported
Generating payloads for Groovy1...
Generating payloads for Hibernate1...
Generating payloads for Hibernate2...
    Error while generating or serializing payload
    java.sql.SQLException: DataSource name cannot be empty string
    	at javax.sql.rowset.BaseRowSet.setDataSourceName(BaseRowSet.java:855)
    	at com.sun.rowset.JdbcRowSetImpl.setDataSourceName(JdbcRowSetImpl.java:4307)
    	at ysoserial.payloads.Hibernate2.getObject(Hibernate2.java:58)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'Hibernate2' and it will not be supported
Generating payloads for JBossInterceptors1...
Generating payloads for JRMPClient...
Generating payloads for JRMPListener...
    Error while generating or serializing payload
    java.lang.NumberFormatException: For input string: ""
    	at java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
    	at java.lang.Integer.parseInt(Integer.java:592)
    	at java.lang.Integer.parseInt(Integer.java:615)
    	at ysoserial.payloads.JRMPListener.getObject(JRMPListener.java:42)
    	at ysoserial.payloads.JRMPListener.getObject(JRMPListener.java:34)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'JRMPListener' and it will not be supported
Generating payloads for JSON1...
Generating payloads for JavassistWeld1...
Generating payloads for Jdk7u21...
Generating payloads for Jython1...
    Error while generating or serializing payload
    java.lang.IllegalArgumentException: Unsupported command  []
    	at ysoserial.payloads.Jython1.getObject(Jython1.java:52)
    	at ysoserial.payloads.Jython1.getObject(Jython1.java:42)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'Jython1' and it will not be supported
Generating payloads for MozillaRhino1...
Generating payloads for Myfaces1...
Generating payloads for Myfaces2...
    Error while generating or serializing payload
    java.lang.IllegalArgumentException: Command format is: <base_url>:<classname>
    	at ysoserial.payloads.Myfaces2.getObject(Myfaces2.java:47)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'Myfaces2' and it will not be supported
Generating payloads for ROME...
Generating payloads for Spring1...
Generating payloads for Spring2...
Generating payloads for URLDNS...
    Error while generating or serializing payload
    java.net.MalformedURLException: no protocol: 
    	at java.net.URL.<init>(URL.java:593)
    	at ysoserial.payloads.URLDNS.getObject(URLDNS.java:56)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'URLDNS' and it will not be supported
Generating payloads for Vaadin1...
Generating payloads for Wicket1...
    Error while generating or serializing payload
    java.lang.IllegalArgumentException: Bad command format.
    	at ysoserial.payloads.Wicket1.getObject(Wicket1.java:59)
    	at ysoserial.payloads.Wicket1.getObject(Wicket1.java:49)
    	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
  ERROR: Errored while generating 'Wicket1' and it will not be supported
DONE!  Successfully generated 0 static payloads and 22 dynamic payloads.  Skipped 8 unsupported payloads.
```

At completion, the `data/ysoserial_payloads.json` file is overwritten and the 22 dynamic payloads are ready for use within the framework.  Afterward, the developer should follow the standard `git` procedures to `add` and `commit` the new JSON file  before generating a pull request and landing the updated JSON into the framework's `master` branch.

[1]: https://github.com/pimps/ysoserial-modified/blob/e71f70dbc5e8c27d72873014ac5cb7766f4b5b94/src/main/java/ysoserial/payloads/util/CmdExecuteHelper.java#L11-L30
[2]: https://github.com/rapid7/metasploit-framework/blob/d580e7d12218fbf62b190a0c0c6d25f43b8aa5be/modules/exploits/multi/http/shiro_rememberme_v124_deserialize.rb
