Stealth is an important feature to think about during exploit development. If your exploit gets caught all the time, it doesn't matter how awesome or how technically challenging your exploit is, it is most likely not very usable in a real penetration test. Browser exploits in particular, heavily rely on JavaScript to trigger vulnerabilities, therefore a lot of antivirus or signature-based intrusion detection/prevention systems will scan the JavaScript and flag specific lines as malicious. The following code used to be considered as MS12-063 by multiple [antivirus vendors](https://www.virustotal.com/en/file/90fdf2beab48cf3c269f70d8c9cf7736f3442430ea023d06b65ff073f724870e/analysis/1388888489/) even though it is not necessarily harmful or malicious, we'll use this as an example throughout the wiki:

```javascript
var arrr = new Array();
arrr[0] = windows.document.createElement("img");
arrr[0]["src"] = "a";
```

To avoid getting flagged, there are some common evasive tricks we can try. For example, you can manually modify the code a little bit to make it not recognizable by any signatures. Or if the antivirus relies on cached webpages to scan for exploits, it is possible to make the browser not cache your exploit so you stay undetected. Or in this case, you can obfuscate your code, which is what this writeup will focus on.

In Metasploit, there are three common ways to obfuscate your JavaScript. The first one is simply by using the ```rand_text_alpha``` method (in [Rex](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/text.rb#L1223)) to randomize your variables. The second one is by using the [ObfuscateJS](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/exploitation/obfuscatejs.rb) class. And the third option is the [JSObfu](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/exploitation/jsobfu.rb) class.

## The rand_text_alpha trick

Using ```rand_text_alpha``` is the most basic form of evasion, but also the least effective. If this is your choice, you should randomize whatever can be randomized without breaking the code.

By using the above MS12-063, here's how you would use ```rand_text_alpha```:

```ruby
# Randomizes the array variable
# Max size = 6, Min = 3
var_array = rand_text_alpha(rand(6) + 3)

# Randomizes the src value
val_src   = rand_text_alpha(1)

js = %Q|
var #{var_array} = new Array();
#{var_array}[0] = windows.document.createElement("img");
#{var_array}[0]["src"] = "#{val_src}";
|
```

## The ObfuscateJS class

The ObfuscateJS class is like the ```rand_text_alpha``` technique on steroids. It allows you to replace symbol names such as variables, methods, classes, and namespaces. It can also obfuscate strings by either randomly using ```fromCharCode``` or ```unescape```. And lastly, it can strip JavaScript comments, which is handy because exploits often are hard to understand and read so you need comments to remember why something is written in a specific way, but you don't want to show or leak those comments in a pentest.

To use ObfuscateJS, let's use the MS12-063 example again to demonstrate. If you feel like following the steps yourself without writing a module, what you can do is go ahead and run ```msfconsole```, and then switch to irb, like this:


```
$ ./msfconsole -q
msf > irb
[*] Starting IRB shell...

>> 
```

And then you are ready to go.

The first thing you do with ObfuscateJS is you need to initialize it with the JavaScript you want to obfuscate, so in this case, begin like the following:

```
js = %Q|
var arrr = new Array();
arrr[0] = windows.document.createElement("img");
arrr[0]["src"] = "a";
|

obfu = ::Rex::Exploitation::ObfuscateJS.new(js)
```

```obfu``` should return a [Rex::Exploitation::ObfuscateJS](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/exploitation/obfuscatejs.rb) object. It allows you to do a lot of things, you can really just call ```methods```, or look at the source to see what methods are available (with additional API documentation). But for demo purposes, we'll showcase the most common one: the ```obfuscate``` method.

To actually obfuscate, you need to call the ```obfuscate``` method. This method accepts a symbols argument that allows you to manually specify what symbol names (variables, methods, classes, etc) to obfuscate, it should be in a hash like this:

```ruby
{
	'Variables'  => [ 'var1', ... ],
	'Methods'    => [ 'method1', ... ],
	'Namespaces' => [ 'n', ... ],
	'Classes'    => [ { 'Namespace' => 'n', 'Class' => 'y'}, ... ]
}
```

So if I want to obfuscate the variable ```arrr```, and I want to obfuscate the src string, here's how:

```
>> obfu.obfuscate('Symbols' => {'Variables'=>['arrr']}, 'Strings' => true)
=> "\nvar QqLFS = new Array();\nQqLFS[0] = windows.document.createElement(unescape(String.fromCharCode(  37, 54, 071, 045, 0x36, 0144, 37, 066, 067 )));\nQqLFS[0][String.fromCharCode(  115, 0x72, 0143 )] = unescape(String.fromCharCode(  045, 0x36, 0x31 ));\n"
```

In some cases, you might actually want to know the obfuscated version of a symbol name. One scenario is calling a JavaScript function from an element's event handler, such as this:

```
<html>
<head>
<script>
function test() {
	alert("hello, world!");
}
</script>
</head>
<body onload="test();">
</body>
</html>
```

The obfuscated version would look like the following:

```ruby
js = %Q|
function test() {
	alert("hello, world!");
}
|

obfu = ::Rex::Exploitation::ObfuscateJS.new(js)
obfu.obfuscate('Symbols' => {'Methods'=>['test']}, 'Strings' => true)

html = %Q|
<html>
<head>
<script>
#{js}
</script>
</head>
<body onload="#{obfu.sym('test')}();">
</body>
</html>
|

puts html
```

## The JSObfu class

The JSObfu class is like ObfuscateJS' cousin, so it shares some similar obfuscation characteristics. The main difference is that it uses [rkelly](https://rubygems.org/gems/rkelly) (a ruby-based JavaScript parser) for smarter code mutation. You no longer have to manually specify what symbol names to change, it just knows.

Let's get back to irb again to demonstrate how easy it is to use JSObfu:

```
$ ./msfconsole -q
msf > irb
[*] Starting IRB shell...

>> 
```

This time we'll do a "hello world" example:

```
>> js = ::Rex::Exploitation::JSObfu.new %Q|alert('hello, world!');|
=> alert('hello, world!');
>> js.obfuscate
=> nil
```

And here's the output:

```
>> puts js
alert(String.fromCharCode(104,0145,108,0x6c,0157,44,0x20,0x77,0x6f,0x72,0154,0x64,041));
```

Like ObfuscateJS, if you need to get the randomized version of a symbol name, you can still do that. We'll demonstrate this with the following example:

```ruby
>> js = ::Rex::Exploitation::JSObfu.new %Q|function test() { alert("hello"); }|
=> function test() {
  alert("hello");
}
>> js.obfuscate
```

Say we want to know the randomized version of the method name "test":

```ruby
>> puts js.sym('test')
kMDXP9YNGDV
```

OK, double check right quick:

```
>> puts js
function kMDXP9YNGDV() {
  alert(String.fromCharCode(0150,101,0154,108,111));
}
```

Yup, that looks good to me.

## Breakage

Please note that when you use obfuscation, occasionally it is possible to make the exploit a little bit less reliable. Because of this, many of the official Metasploit modules don't have obfuscation enabled by default, usually it's a datastore option.

## Reference(s)

https://community.rapid7.com/community/metasploit/blog/2011/07/08/jsobfu