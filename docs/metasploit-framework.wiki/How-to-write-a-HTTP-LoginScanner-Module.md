This is a step-by-step guide on how to write a HTTP login module using the latest LoginScanner and Credential APIs.

Before we begin, it's probably a good idea to read [[Creating Metasploit Framework LoginScanners|./Creating-Metasploit-Framework-LoginScanners.md]], which explains about the APIs in-depth. The LoginScanner API can be found in the [lib/metasploit/framework/loginscanner](https://github.com/rapid7/metasploit-framework/tree/master/lib/metasploit/framework/login_scanner) directory, and the Credential API can found as a [metasploit-credential gem here](https://github.com/rapid7/metasploit-credential). You will most likely want to read them while writing the login module.

## Step 1: Set up your target environment

For our demonstration, we will be using [Symantec Web Gateway](https://www.broadcom.com/products/cyber-security/web-and-email/gateway/). A trial is available at the vendor's website. Obviously downloading/installing it would be your first step.

## Step 2: Set up a client

The purpose of setting up a client is to sample the login request and response. Normally you can do this with:

* **A web browser plus a sniffer**

  1. For the sniffer, you can download [Wireshark](https://www.wireshark.org/download.html), and have it running.
  2. Use a web browser to login.
  3. Go back to Wireshark and save the HTTP request, this is exactly what you will send in the login module. You will also need to save the HTTP response so that you can check for a successful and a failed login.

* **A browser with Burp**

  [Burp](http://portswigger.net/burp/download.html) is a tool for performing security testing of web applications. You can download the free version from the vendor's website. In some cases, Burp is way better than a sniffer because you can modify HTTP requests, it's also a very convenient way to capture HTTPS traffic.

  Here's what you do.

  1. Start Burp.
  2. Configure your web browser's proxy so Burp can forward traffic.
  3. Use the web browser to login.
  4. Go back to Burp, you can find the history of all the requests and responses.

For our example, this is the request the browser sends to Symantec Web Gateway:

```
POST /spywall/login.php HTTP/1.1
Host: 192.168.1.176
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:27.0) Gecko/20100101 Firefox/27.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://192.168.1.176/spywall/login.php
Cookie: PHPSESSID=otgam4mgjrl00h2esk3o2npt05
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 54

USERNAME=gooduser&PASSWORD=GoodPassword&loginBtn=Login
```

And this is the response Symantec Web Gateway returns for a successful login:

```
HTTP/1.1 302 Found
Date: Tue, 12 May 2015 19:32:31 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: PHPSESSID=vmb56vhd7740oqcmth8cqtagq5; path=/; secure; HttpOnly
Location: https://192.168.1.176/spywall/executive_summary.php
Content-Length: 0
Keep-Alive: timeout=15, max=5000
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

A failed login response is an HTTP 200 with the following message in the body:

```
We're sorry, but the username or password you have entered is incorrect.  Please retype your username and password. The username and password are case sensitive.
```

## Step 3: Start with a LoginScanner template

Your login module mainly consists of three components: the LoginScanner portion, the auxiliary portion, and rpsec. The actual HTTP requests and responses are handled in the LoginScanner portion, so we'll start from there.

Your most basic HTTP LoginScanner template will look like this:

```ruby
require 'metasploit/framework/login_scanner/http'

module Metasploit
  module Framework
    module LoginScanner
      class SymantecWebGateway < HTTP


        # Attempts to login to the server.
        #
        # @param [Metasploit::Framework::Credential] credential The credential information.
        # @return [Result] A Result object indicating success or failure
        def attempt_login(credential)

        end

      end
    end
  end
end
```

Save it under lib/metasploit/framework/login_scanner/.

**The #attempt_login method**

The #attempt_login is called automatically. You can write your entire login code there, but it's better to break in down into multiple methods so that the code is cleaner, and easier to document and rspec. Typically, all you want #attempt_login to do is focusing on crafting the Result object, pass it to a custom #login routine, and then return the Result object. It almost always looks something like this:

```ruby
def attempt_login(credential)
  # Default Result
  result_opts = {
    credential: credential,
    status: Metasploit::Model::Login::Status::INCORRECT,
    proof: nil,
    host: host,
    port: port,
    protocol: 'tcp'
  }

  # Merge login result
  # credential.public is the username
  # credential.private is the password
  result_opts.merge!(do_login(credential.public, credential.private))

  # Return the Result object
  Result.new(result_opts)
end
```

Notice that:

* By default, our proof is nil.
* The status is Metasploit::Model::Login::Status::INCORRECT.
* We're calling #do_login, which is our custom login method.
* The #do_login method will have to update status and proof before we return the Result object.

**The custom login method**

Ok, now let's talk about building this #do_login method. This is where we send the same HTTP request we sampled earlier.

If you're already familiar with writing a Metasploit module that sends an HTTP request, the first thing that comes to mind is probably using the [[HttpClient|How to Send an HTTP Request Using HttpClient]]. Well, you can't do that at all over here, so we have to fall back to [[Rex::Proto::Http::Client|How to send an HTTP request using Rex Proto Http Client]]. Fortunately for you, we made all this a little bit easier by creating another request called #send_request, here's an example of how to use that:


```ruby
send_request({'uri'=>'/'})
```

You will rely on this method a lot to accomplish most of what you need to do here.

Ok, now, let's move on and talk about how to use #send_request to send a login request. Remember in the login request, there is actually a PHPSESSID cookie, you should obtain this first. Usually the web application will give you the session cookie when you request the login page for the very first time, and this happens a lot.

Here's an example of how to grab PHPSESSID:

```ruby
def get_session_id
  login_uri = normalize_uri("#{uri}/spywall/login.php")
  res = send_request({'uri' => login_uri})
  sid = res.get_cookies.scan(/(PHPSESSID=\w+);*/).flatten[0] || ''
  return sid
end
```

Now that you have a session ID, you can finally make the login request. Remember in the sample, we have to submit the username, password, loginBtn as a POST request. So let's do that with #send_request:

```ruby
protocol  = ssl ? 'https' : 'http'
peer      = "#{host}:#{port}"
login_uri = normalize_uri("#{uri}/spywall/login.php")

res = send_request({
  'uri' => login_uri,
  'method' => 'POST',
  'cookie' => get_session_id,
  'headers' => { 'Referer' => "#{protocol}://#{peer}/#{login_uri}" },
  'vars_post' => {
    'USERNAME' => username,
    'PASSWORD' => password,
    'loginBtn' => 'Login' # Found in the HTML form
  }
})
```

Now that the request is sent, we need to check the response (the res variable). Typically, you have a few choices to determine a successful login:

* **Check the HTTP response code**. In this case, we have a 302 (redirect), but know that sometimes the response code can lie so this should not be your first choice.
* **Check the HTML**. With some web applications, you might get a "successful login" message, and you can regex that. This is most likely the most accurate way.
* **Check the location header**. In our case, Symantec returns a 302 and contains no body. But it redirects us to a spywall/executive_summary.php page in the location header, so we can use that. We can also try to access executive_summary.php with a renewed session ID, and make sure we can actually see the admin interface, but requesting an extra page adds more penalty to performance, so this is up to you.

In the end, your custom login method will probably look something like this:

```ruby
def do_login(username, password)
  protocol  = ssl ? 'https' : 'http'
  peer      = "#{host}:#{port}"
  login_uri = normalize_uri("#{uri}/spywall/login.php")

  res = send_request({
    'uri' => login_uri,
    'method' => 'POST',
    'cookie' => get_session_id,
    'headers' => {
      'Referer' => "#{protocol}://#{peer}/#{login_uri}"
    },
    'vars_post' => {
      'USERNAME' => username,
      'PASSWORD' => password,
      'loginBtn' => 'Login' # Found in the HTML form
    }
  })

  if res && res.headers['Location'].include?('executive_summary.php')
    return {:status => LOGIN_STATUS::SUCCESSFUL, :proof => res.to_s}
  end

  {:proof => res.to_s}
end
```

The [exact statuses](https://github.com/rapid7/metasploit-model/blob/d4c4f444c79937698dc703f89c0a4c576cde628c/lib/metasploit/model/login/status.rb) you can return are:

| Constant | Purpose |
| ------------- | --------- |
| Metasploit::Model::Login::Status::DENIED_ACCESS | Access is denied |
| Metasploit::Model::Login::Status::DISABLED | Account is disabled |
| Metasploit::Model::Login::Status::INCORRECT | Credential is incorrect |
| Metasploit::Model::Login::Status::LOCKED_OUT | Account has been locked out |
| Metasploit::Model::Login::Status::NO_AUTH_REQUIRED | No authentication |
| Metasploit::Model::Login::Status::SUCCESSFUL | Successful login |
| Metasploit::Model::Login::Status::UNABLE_TO_CONNECT | Unable to connect to the service |
| Metasploit::Model::Login::Status::UNTRIED | Credential has not been tried |
| Metasploit::Model::Login::Status::ALL | All the above (An array) |

When you're done, your code will look something like this:

<https://github.com/rapid7/metasploit-framework/blob/master/lib/metasploit/framework/login_scanner/symantec_web_gateway.rb>

## Step 4: Write the auxiliary module

The auxiliary module acts more like an user-interface. You describe what the module does, handles options, initializes objects, and do reporting.

A basic auxiliary module template in our case would be something like this:

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/symantec_web_gateway'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Symantec Web Gateway Login Utility',
        'Description' => %q{
          This module will attempt to authenticate to a Symantec Web Gateway.
        },
        'Author' => [ 'sinn3r' ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true,
          'SSLVersion' => 'TLS1'
        }
      )
    )
  end

  def run_host(ip)
  end

end
```

Save it under modules/auxiliary/scanner/http/.

Our main method is #run_host, so we'll begin there. But before we do, we must initialize your LoginScanner object. The following is an example of how you will probably write it.

```ruby
def scanner(ip)
  @scanner ||= lambda {
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file:       datastore['PASS_FILE'],
      password:        datastore['PASSWORD'],
      user_file:       datastore['USER_FILE'],
      userpass_file:   datastore['USERPASS_FILE'],
      username:        datastore['USERNAME'],
      user_as_pass:    datastore['USER_AS_PASS']
    )

    return Metasploit::Framework::LoginScanner::SymantecWebGateway.new(
      configure_http_login_scanner(
        host: ip,
        port: datastore['RPORT'],
        cred_details:       cred_collection,
        stop_on_success:    datastore['STOP_ON_SUCCESS'],
        bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5
      ))
    }.call
end
```


Notice that this scanner method can be called multiple times, but the use of [lambda](http://rubymonk.com/learning/books/1-ruby-primer/chapters/34-lambdas-and-blocks-in-ruby/lessons/77-lambdas-in-ruby) will allow the LoginScanner object to initialize only once. After that first time, every time the method is called, it will just return @scanner instead of going through the whole initialization process again.

In some cases you might need to pass more datastore options, maybe not. For example, if you want to allow the URI to be configurable (which is also already an accessor in [Metasploit::Framework::LoginScanner::HTTP](https://github.com/rapid7/metasploit-framework/blob/master/lib/metasploit/framework/login_scanner/http.rb#L26)), then you have to create and pass datastore['URI'] to configure_http_login_scanner too, like so:

```ruby
uri: datastore['URI']
```

And then in your LoginScanner, pass ```uri``` to #send_request:

```ruby
send_request({'uri'=>uri})
```

At this point, the scanner method holds our Metasploit::Framework::LoginScanner::SymantecWebGateway object. If we call the #scan! method, it will trigger the #attempt_login method we wrote earlier, and then yield the Result object. Basically like this:

```ruby
scanner(ip).scan! do |result|
  # result = Our Result object
end
```

With the Result object, we can start reporting. In most cases, you will probably be using #create_credential_login to report a successful login. And use #invalidate_login to report a bad one.

**Reporting a valid credential**

The credential API knows a lot about a credential, such as when it was used, how it was used, serviced tried, target IP, port, etc, etc. So when we report, that's how much information we are storing for every credential. To make credential reporting easy to use, all you need to do is call the #store_valid_credential method like this:

```ruby
store_valid_credential(
  user: result.credential.public,
  private: result.credential.private,
  private_type: :password, # This is optional
  proof: nil, # This is optional
)
```

**Report an invalid credential**

Here's another example you can use:

```ruby
# Reports a bad credential.
#
# @param [String] ip Target host
# @param [Fixnum] port Target port
# @param [Result] The Result object
# @return [void]
def report_bad_cred(ip, rport, result)
  invalidate_login(
    address: ip,
    port: rport,
    protocol: 'tcp',
    public: result.credential.public,
    private: result.credential.private,
    realm_key: result.credential.realm_key,
    realm_value: result.credential.realm,
    status: result.status,
    proof: result.proof
  )
end
```

At this point, you're pretty much done with the auxiliary module. It will probably look something like this:
<https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/http/symantec_web_gateway_login.rb>

## Test

And finally, make sure your module actually works.

Test for a successful login:

```msf
msf auxiliary(symantec_web_gateway_login) > run

[+] 192.168.1.176:443 SYMANTEC_WEB_GATEWAY - Success: 'sinn3r:GoodPassword'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(symantec_web_gateway_login) >
```

Test for a failed login:

```msf
msf auxiliary(symantec_web_gateway_login) > run

[-] 192.168.1.176:443 SYMANTEC_WEB_GATEWAY - Failed: 'sinn3r:BadPass'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(symantec_web_gateway_login) >
```
