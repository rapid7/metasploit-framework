require 'rex/proto/http/response'

get_cookies_test_1 = '
HTTP/1.1 200 OK
Date: Fri, 26 Apr 2013 12:43:12 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.4.6-1ubuntu1.2
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: private, max-age=10800, pre-check=10800
Last-Modified: Fri, 26 Apr 2013 12:01:52 GMT
Vary: Accept-Encoding
Content-Length: 63951
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">'

get_cookies_test_2 = '
HTTP/1.1 200 OK
Date: Fri, 26 Apr 2013 08:44:54 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.4.6-1ubuntu1.2
Set-Cookie: phpMyAdmin=gpjif0gtpqbvfion91ddtrq8p8vgjtue; path=/phpmyadmin/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: private, max-age=10800, pre-check=10800
Last-Modified: Sun, 12 Aug 2012 13:38:18 GMT
Set-Cookie: pma_lang=en; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: pma_collation_connection=utf8_general_ci; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: pma_mcrypt_iv=mF1NmTE64IY%3D; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: phpMyAdmin=fmilioji5cn4m8bo5vjrrr6q9cada954; path=/phpmyadmin/; HttpOnly
Vary: Accept-Encoding
Content-Length: 7356
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=utf-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'

get_cookies_test_3 = '
HTTP/1.1 200 OK
Date: Fri, 26 Apr 2013 08:44:54 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.4.6-1ubuntu1.2
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: private, max-age=10800, pre-check=10800
Last-Modified: Sun, 12 Aug 2012 13:38:18 GMT
Set-Cookie: pma_lang=en; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: pma_collation_connection=utf8_general_ci; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: pma_mcrypt_iv=mF1NmTE64IY%3D; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: phpMyAdmin=fmilioji5cn4m8bo5vjrrr6q9cada954; path=/phpmyadmin/; HttpOnly
Set-Cookie: superC00kie!=stupidcookie; Path=/parp/; domain=.foo.com; HttpOnly; Expires=Wed, 13-Jan-2012 22:23:01 GMT; Secure
Vary: Accept-Encoding
Content-Length: 7356
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=utf-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'

get_cookies_test_4 ='
HTTP/1.1 200 OK
Date: Fri, 26 Apr 2013 08:44:54 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.4.6-1ubuntu1.2
Set-Cookie: phpMyAdmin=gpjif0gtpqbvfion91ddtrq8p8vgjtue; path=/phpmyadmin/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: private, max-age=10800, pre-check=10800
Last-Modified: Sun, 12 Aug 2012 13:38:18 GMT
Set-Cookie: pma_lang=en; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: pma_collation_connection=utf8_general_ci; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: pma_mcrypt_iv=mF1NmTE64IY%3D; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
Set-Cookie: phpMyAdmin=; path=/phpmyadmin/; HttpOnly
Vary: Accept-Encoding
Content-Length: 7356
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=utf-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'

describe Rex::Proto::Http::Response do
	R = Rex::Proto::Http::Response
	it "get_cookies returns empty string for no Set-Cookies" do
		resp = R.new()
		resp.parse(get_cookies_test_1)
		resp.get_cookies.should eq("")
	end

	it "get_cookies returns 5 cookies for test 2" do
		resp = R.new()
		resp.parse(get_cookies_test_2)
		resp.get_cookies.split(';').count.should eq(5)
	end

	it "get_cookies returns 5 cookies for test 3 and parses full cookie" do
		resp = R.new()
		resp.parse(get_cookies_test_3)
		resp.get_cookies.split(';').count.should eq(5)
		resp.get_cookies.include?("superC00kie!=stupidcookie;").should be_true
	end

	it "get_cookies returns 5 cookies for test 4 and parses empty value" do
		resp = R.new()
		resp.parse(get_cookies_test_4)
		resp.get_cookies.split(';').count.should eq(5)
		resp.get_cookies.include?("phpMyAdmin=;").should be_true
	end
end
