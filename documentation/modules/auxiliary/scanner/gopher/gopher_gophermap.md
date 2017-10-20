## Vulnerable Application

  Any gopher server will work.  There seems to only be [a few left](https://en.wikipedia.org/wiki/Gopher_(protocol)#Server_software)
   in 2017.

  A few options for local installation and testing are below.

### Docker Install

A [dockerized gopher server written in Go](https://hub.docker.com/r/prodhe/gopher/) is available.  To install and run this, with content being
served out of a temporary directory in which you'll be left:

```
$  docker pull prodhe/gopher
Using default tag: latest
latest: Pulling from prodhe/gopher
627beaf3eaaf: Already exists
8800e3417eb1: Pull complete
d9f3bcdad0eb: Pull complete
c018073abd26: Pull complete
b2855f535c50: Pull complete
23480a2f73d8: Pull complete
1555a5435ec5: Pull complete
0728d289e0fc: Pull complete
6f6f265b58ee: Pull complete
Digest: sha256:69931d56946d192d9bd155a88b6f365cb276e9edf453129d374e64d244d1edaa
Status: Downloaded newer image for prodhe/gopher:latest
$  cd `mktemp -d`;
$  sudo docker run --rm -d -it --name gopher_test -v `pwd -P`:/public  -p 70:70  prodhe/gopher
2017/10/20 16:45:01 Serving /public/ at localhost:70
$ date > test.txt
$ echo HELLO > README.md
```

*NOTE*: Don't forget to `docker stop` the container ID returned from the `docker run` command just run above:
```
$ docker stop X
X
```


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

### Docker Gopher Server
```
msf > use auxiliary/scanner/gopher/gopher_gophermap
msf auxiliary(gopher_gophermap) > set RHOSTS localhost
RHOSTS => localhost
msf auxiliary(gopher_gophermap) > run

[+] 127.0.0.1:70          -   Text file: README.md
[+] 127.0.0.1:70          -     Path: localhost:70/README.md
[+] 127.0.0.1:70          -   Text file: test.txt
[+] 127.0.0.1:70          -     Path: localhost:70/test.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
### Gopher-server on Ubuntu 16.04

```
msf > use auxiliary/scanner/gopher/gopher_gophermap
msf auxiliary(gopher_gophermap) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
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
