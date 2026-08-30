Stealth is an important feature to think about during exploit development. If your exploit gets caught all the time, it doesn't matter how awesome or how technically challenging your exploit is, it is most likely not very usable in a real penetration test. Browser exploits in particular, heavily rely on JavaScript to trigger vulnerabilities, therefore a lot of antivirus or signature-based intrusion detection/prevention systems will scan the JavaScript and flag specific lines as malicious. The following code used to be considered as MS12-063 by multiple [antivirus vendors](https://www.virustotal.com/en/file/90fdf2beab48cf3c269f70d8c9cf7736f3442430ea023d06b65ff073f724870e/analysis/1388888489/) even though it is not necessarily harmful or malicious, we'll use this as an example throughout the wiki:

```javascript
var arrr = new Array();
arrr[0] = windows.document.createElement("img");
arrr[0]["src"] = "a";
```

To avoid getting flagged, there are some common evasive tricks we can try. For example, you can manually modify the code a little bit to make it not recognizable by any signatures. Or if the antivirus relies on cached webpages to scan for exploits, it is possible to make the browser not cache your exploit so you stay undetected. Or in this case, you can obfuscate your code, which is what this writeup will focus on.

In Metasploit, there are three common ways to obfuscate your JavaScript. The first one is simply by using the ```rand_text_alpha``` method (in [Rex](https://github.com/rapid7/rex-text/blob/3bb11cb5c9997096a82a4e160fcb31c152385a9a/lib/rex/text/rand.rb#L127-L132)) to randomize your variables. The second one is by using the [ObfuscateJS](https://github.com/rapid7/rex-exploitation/blob/f3058a0737ba89fd116f99a8381a409bba6a53fa/lib/rex/exploitation/obfuscatejs.rb) class. And the third option is the [JSObfu](https://github.com/rapid7/rex-exploitation/blob/f3058a0737ba89fd116f99a8381a409bba6a53fa/lib/rex/exploitation/jsobfu.rb) class.

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

The ObfuscateJS class is like the ```rand_text_alpha``` technique on steroids, but even better. It allows you to replace symbol names such as variables, methods, classes, and namespaces. It can also obfuscate strings by either randomly using ```fromCharCode``` or ```unescape```. And lastly, it can strip JavaScript comments, which is handy because exploits often are hard to understand and read so you need comments to remember why something is written in a specific way, but you don't want to show or leak those comments in a pentest.

To use ObfuscateJS, let's use the MS12-063 example again to demonstrate. If you feel like following the steps yourself without writing a module, what you can do is go ahead and run ```msfconsole```, and then switch to irb, like this:


```
$ ./msfconsole -q
msf > irb
[*] Starting IRB shell...

>> 
```

And then you are ready to go.

The first thing you do with ObfuscateJS is you need to initialize it with the JavaScript you want to obfuscate, so in this case, begin like the following:

```ruby
js = %Q|
var arrr = new Array();
arrr[0] = windows.document.createElement("img");
arrr[0]["src"] = "a";
|

obfu = ::Rex::Exploitation::ObfuscateJS.new(js)
```

```obfu``` should return a [Rex::Exploitation::ObfuscateJS](https://github.com/rapid7/rex-exploitation/blob/f3058a0737ba89fd116f99a8381a409bba6a53fa/lib/rex/exploitation/obfuscatejs.rb) object. It allows you to do a lot of things, you can really just call ```methods```, or look at the source to see what methods are available (with additional API documentation). But for demo purposes, we'll showcase the most common one: the ```obfuscate``` method.

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

```html
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

The JSObfu class used to be ObfuscateJS' cousin, but it has been completely rewritten since September 2014, and packaged as a [gem](https://rubygems.org/gems/jsobfu). The obfuscation is more complex and you can actually tell it to obfuscate multiple times. You also no longer have to manually specify what symbol names to change, it just knows.

**Trying JSObfu in Rex**

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

```javascript
window[(function () { var _d="t",y="ler",N="a"; return N+y+_d })()]((function () { var f='d!',B='orl',Q2='h',m='ello, w'; return Q2+m+B+f })());
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
>> puts js.sym("test")
_
```

OK, double check right quick:

```
>> puts js
function _(){window[(function () { var N="t",r="r",i="ale"; return i+r+N })()](String.fromCharCode(0150,0x65,0154,0x6c,0x6f));}
```

Yup, that looks good to me.

And finally, let's try to obfuscate a few times to see how that goes:

```
>> js = ::Rex::Exploitation::JSObfu.new %Q|alert('hello, world!');|
=> alert('hello, world!');
>> js.obfuscate(:iterations=>3)
=> window[String[((function(){var s=(function () { var r="e"; return r })(),Q=(function () { var I="d",dG="o"; return dG+I })(),c=String.fromCharCode(0x66,114),w=(function () { var i="C",v="r",f="omCh",j="a"; return f+j+v+i })();return c+w+Q+s;})())](('Urx'.length*((0x1*(01*(1*020+5)+1)+3)*'u'.length+('SGgdrAJ'.length-7))+(('Iac'.length*'XLR'.length+2)*'qm'.length+0)),(('l'.length*((function () { var vZ='k'; return vZ })()[((function () { var E="h",t="t",O="leng"; return O+t+E })())]*(0x12*1+0)+'xE'.length)+'h'.length)*(function () { var Z='uA',J='tR',D='x'; return D+J+Z })()[((function () { var m="th",o="g",U="l",Y="en"; return U+Y+o+m })())]+'lLc'.length),('mQ'.length*(02*023+2)+('Tt'.length*'OEzGiMVf'.length+5)),(String.fromCharCode(0x48,0131)[((function () { var i="gth",r="len"; return r+i })())]*('E'.length*0x21+19)+(0x1*'XlhgGJ'.length+4)),(String.fromCharCode(0x69)[((function () { var L="th",Q="n",$="l",I="g",x="e"; return $+x+Q+I+L })())]*('QC'.length*0x2b+3)+(01*26+1)))]((function(){var C=String[((function () { var w="rCode",j="mCha",A="fr",B="o"; return A+B+j+w })())]((6*0x10+15),('riHey'.length*('NHnex'.length*0x4+2)+4),(01*95+13),(1*('Z'.length*(0x1*(01*(0x3*6+5)+1)+18)+12)+46),(0x1*(01*013+6)+16)),JQ=String[((function () { var NO="ode",T="rC",HT="fromCha"; return HT+T+NO })())](('J'.length*0x54+17),(0x2*051+26),('TFJAGR'.length*('ymYaSJtR'.length*'gv'.length+0)+12),(01*0155+2),(0xe*'FBc'.length+2),(0x1*22+10),(3*(01*043+1)+11)),g=(function(){var N=(function () { var s='h'; return s })();return N;})();return g+JQ+C;})());
```

**Using JSObfu for module development**

When you are writing a module, you should not call Rex directly like the above examples. Instead, you should be using the ```#js_obfuscate``` method found in [JSObfu mixin](https://github.com/rapid7/rex-exploitation/blob/f3058a0737ba89fd116f99a8381a409bba6a53fa/lib/rex/exploitation/jsobfu.rb). When you're using JavaScript in your module, always do write it like this:

```ruby
# This returns a Rex::Exploitation::JSObfu object
js = js_obfuscate(your_code)
```

Note that by default, even though your module is calling the #js_obfuscate method, obfuscation will not kick in unless the user sets the JsObfuscate datastore option. This option is an OptInt, which allows you to set the number of times to obfuscate (default is 0).
