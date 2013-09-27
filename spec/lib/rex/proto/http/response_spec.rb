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

get_cookies_test_5 ='
HTTP/1.1 200 OK
Date: Wed, 25 Sep 2013 20:29:23 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.4.9-4ubuntu2.2
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Last-Modified: Wed, 25 Sep 2013 20:29:23 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Pragma: no-cache
Set-Cookie: wordpressuser_a97c5267613d6de70e821ff82dd1ab94=admin; path=/wordpress-2.0/, wordpresspass_a97c5267613d6de70e821ff82dd1ab94=c3284d0f94606de1fd2af172aba15bf3; path=/wordpress-2.0/
Vary: Accept-Encoding
Content-Length: 0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'

describe Rex::Proto::Http::Response do
  it 'get_cookies returns empty string for no Set-Cookies' do
    resp = described_class.new()
    resp.parse(get_cookies_test_1)
    resp.get_cookies.should eq('')
  end

  it 'get_cookies returns 5 cookies for test 2' do
    resp = described_class.new()
    resp.parse(get_cookies_test_2)
    cookies = resp.get_cookies
    cookies.should_not be_nil
    cookies.should_not be ''
    cookies_array = cookies.split(';').map(&:strip)
    cookies_array.count.should eq(5)
    cookies_array.should =~ %w(
      pma_lang=en
      pma_collation_connection=utf8_general_ci
      pma_mcrypt_iv=mF1NmTE64IY%3D
      phpMyAdmin=fmilioji5cn4m8bo5vjrrr6q9cada954
      phpMyAdmin=gpjif0gtpqbvfion91ddtrq8p8vgjtue
    )
  end

  it 'get_cookies returns 5 cookies for test 3 and parses full cookie' do
    resp = described_class.new()
    resp.parse(get_cookies_test_3)
    cookies = resp.get_cookies
    cookies.should_not be_nil
    cookies.should_not be ''
    cookies_array = cookies.split(';').map(&:strip)
    cookies_array.count.should eq(5)
    cookies_array.should =~ %w(
      pma_lang=en
      pma_collation_connection=utf8_general_ci
      pma_mcrypt_iv=mF1NmTE64IY%3D
      phpMyAdmin=fmilioji5cn4m8bo5vjrrr6q9cada954
      superC00kie!=stupidcookie
    )
  end

  it 'get_cookies returns 5 cookies for test 4 and parses empty value' do
    resp = described_class.new()
    resp.parse(get_cookies_test_4)
    cookies = resp.get_cookies
    cookies.should_not be_nil
    cookies.should_not be ''
    cookies_array = cookies.split(';').map(&:strip)
    cookies_array.count.should eq(5)
    cookies_array.should =~ %w(
      pma_lang=en
      pma_collation_connection=utf8_general_ci
      pma_mcrypt_iv=mF1NmTE64IY%3D
      phpMyAdmin=
      phpMyAdmin=gpjif0gtpqbvfion91ddtrq8p8vgjtue
    )
  end

  it 'parses multiple cookies in one Set-Cookie header correctly' do
    resp = described_class.new()
    resp.parse(get_cookies_test_5)
    cookies = resp.get_cookies
    cookies.should_not be_nil
    cookies.should_not be ''
    cookies_array = cookies.split(';').map(&:strip)
    cookies_array.count.should eq(2)
    cookies_array.should =~ %w(
      wordpressuser_a97c5267613d6de70e821ff82dd1ab94=admin
      wordpresspass_a97c5267613d6de70e821ff82dd1ab94=c3284d0f94606de1fd2af172aba15bf3
    )
  end
end
