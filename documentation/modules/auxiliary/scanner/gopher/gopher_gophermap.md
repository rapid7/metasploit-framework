## Vulnerable Application

  Any gopher server will work.  There seems to only be [a few left](https://en.wikipedia.org/wiki/Gopher_(protocol)#Server_software)
   in 2017.

### Ubuntu 16.04 Install

First we need to install the server:

```
sudo apt-get install gopher-server
```
Next, we need to build content for the scanner to find.  Gopher works off of a `gophermap`, somewhat similar
to a content index page, where files are listed in a menu type system.

```
echo "<html><h1>hello world</h1></html>" | sudo tee /var/gopher/example.html
echo "foobarbaz" | sudo tee /var/gopher/foobar.txt
sudo mkdir /var/gopher/msf
echo "meterpreter rules" | sudo tee /var/gopher/msf/meterp.txt
sudo wget "https://pbs.twimg.com/profile_images/580131056629735424/2ENTk2K2.png" -O /var/gopher/msf/logo.png

echo -ne "gopher custom gophermap\n\nhHello World\t/example.html\t1.1.1.1\t70\n0Foo File\t/foobar.txt\t1.1.1.1\t70\n1msf\t/msf\t1.1.1.1\t70\nhmetasploit homepage\tURL:http://metasploit.com/\n" | sudo tee /var/gopher/gophermap
sudo chmod +r -R /var/gopher
```

In this case we create an html file, text file, a directory with a text file and png file in it.  Enough content so its nice to look at.
Next we write our `gophermap` file.  The first line is just an intro.  After that, we list our files that the client can access.

The format of these lines is: `XSome text here[TAB]/path/to/content[TAB]example.org[TAB]port`.  The first character, `X` is the file type
which can be referenced in the table below.  The final address (example.org) and PORT are optional.

The following table contains the file types associated with the characters:

| Itemtype | Content                         |
|----------|---------------------------------|
| 0        | Text file                       |
| 1        | Directory                       |
| 2        | CSO name server                 |
| 3        | Error                           |
| 4        | Mac HQX filer                   |
| 5        | PC binary                       |
| 6        | UNIX uuencoded file             |
| 7        | Search server                   |
| 8        | Telnet Session                  |
| 9        | Binary File                     |
| c        | Calendar (not in 2.06)          |
| e        | Event (not in 2.06)             |
| g        | GIF image                       |
| h        | HTML, Hypertext Markup Language |
| i        | inline text type              |
| s        | Sound                           |
| I        | Image (other than GIF)          |
| M        | MIME multipart/mixed message    |
| T        | TN3270 Session                  |

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/gopher/gopher_gophermap```
  4. Do: ```set rhosts [IPs]```
  5. Do: ```run```
  6. You should see the gophermap file printed in a parsed format

## Options

  **PATH**

  It is possible to view content within a directory of the gophermap.  If the intial run shows directory `Directory: foobar`, 
  setting **path** to `/foobar` will enumerate the contents of that folder.  Default: [empty string].

## Scenarios

### Gopher-server on Ubuntu 16.04

```
msf > use auxiliary/scanner/gopher/gopher_gophermap 
msf auxiliary(gopher_gophermap) > set rhosts 192.168.2.137
rhosts => 192.168.2.137
msf auxiliary(gopher_gophermap) > set verbose true
verbose => true
msf auxiliary(gopher_gophermap) > run

[+] 1.1.1.1:70      - gopher custom gophermap
[+] 1.1.1.1:70      - 
[+] 1.1.1.1:70      -   HTML: Hello World
[+] 1.1.1.1:70      -     Path: 1.1.1.1:70/example.html
[+] 1.1.1.1:70      -   Text file: Foo File
[+] 1.1.1.1:70      -     Path: 1.1.1.1:70/foobar.txt
[+] 1.1.1.1:70      -   Directory: msf
[+] 1.1.1.1:70      -     Path: 1.1.1.1:70/msf
[+] 1.1.1.1:70      -   HTML: metasploit homepage
[+] 1.1.1.1:70      -     Path: 1.1.1.1:70/URL:http://metasploit.com/
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
