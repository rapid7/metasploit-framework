Java External Module Library

What is this
--

This is an external module for java coders(actually, java8+ coders). 

Before this, we can use ruby(.rb)(native), ruby(.rb)(external module), python(.py)(external module), go(.go)(external module).

After I added this, now we can use java(.jar)(external module) and java(.java)(external module).

What is required for using this
--

You need a java8+ installed.

make sure you can run `java -version` on your machine.

Using Java External Module : Single Java File Module
--

Single Java File Module is asked by msf organization, as we want the hacking-modules accepted in msf official repo be source, not binary.

And in quite some cases, hackers will not need to use many 3rd party java libs, jdk is enough for use.

So I added a dynamic compile / class-loading mechanism (using apache-dubbo), thus this is now usable.

For an example, see `modules/auxiliary/example.java`

This is a java module.

Notice that there be a special rule for single file java modules: the class name must be equals the file name.

For example, if you want to use `modules/auxiliary/example.java`, you shall:

```
1. move it to a deeper folder (same as other examples, because metasploit need so.)
2. rename it to "single_java_file_demo_scanner.java", as the class in it is named single_java_file_demo_scanner.
3. chmod +777
```

Using Java External Module : Jar Module
--

Jar module mechanism is for more complex use.

Sometimes we need 3rd party java libs.

Also usually java people would not put all things in a single java class, this is weird in normal java world.

So there is a mechanism for using jar file.

Jar file name have no such rule, and you can name it whatever you want, ended with `.jar`. 

For example, if you want to use `modules/auxiliary/example.jar`, you shall:

```
1. move it to a deeper folder (same as other examples, because metasploit need so.)
2. chmod +777
```

If you want to develop an external jar module by yourself, that is easy.
(I assume you be familiar with java and maven here.)

Open `lib/msf/core/modules/external/java` as a maven repo, and you can see jar_demo.

Just write some things as it do(or even, you can simply copy it to somewhere and modify it...)

That should not be hard.

Welcome to java world
--
And hope you have fun.
