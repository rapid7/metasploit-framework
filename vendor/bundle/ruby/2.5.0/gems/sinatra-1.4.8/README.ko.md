# Sinatra

*주의: 이 문서는 영문판의 번역본이며 최신판 문서와 다를 수 있습니다.*

Sinatra는 최소한의 노력으로 루비 기반 웹 애플리케이션을 신속하게 만들 수 있게
해 주는 [DSL](https://en.wikipedia.org/wiki/Domain-specific_language)입니다.

```ruby
# myapp.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

아래의 명령어로 젬을 설치합니다.

```shell
gem install sinatra
```

아래의 명령어로 실행합니다.

```shell
ruby myapp.rb
```

[http://localhost:4567](http://localhost:4567) 를 확인해 보세요.

`gem install thin`도 함께 실행하기를 권장합니다.
thin이 설치되어 있을 경우 Sinatra는 thin을 통해 실행합니다.

## 목차

* [Sinatra](#sinatra)
    * [목차](#목차)
    * [라우터(Routes)](#라우터routes)
        * [조건(Conditions)](#조건conditions)
        * [반환값(Return Values)](#반환값return-values)
        * [커스텀 라우터 매처(Custom Route Matchers)](#커스텀-라우터-매처custom-route-matchers)
    * [정적 파일(Static Files)](#정적-파일static-files)
    * [뷰 / 템플릿(Views / Templates)](#뷰--템플릿views--templates)
        * [리터럴 템플릿(Literal Templates)](#리터럴-템플릿literal-templates)
        * [가능한 템플릿 언어들(Available Template Languages)](#가능한-템플릿-언어들available-template-languages)
            * [Haml 템플릿](#haml-템플릿)
            * [Erb 템플릿](#erb-템플릿)
            * [Builder 템플릿](#builder-템플릿)
            * [Nokogiri 템플릿](#nokogiri-템플릿)
            * [Sass 템플릿](#sass-템플릿)
            * [SCSS 템플릿](#scss-템플릿)
            * [Less 템플릿](#less-템플릿)
            * [Liquid 템플릿](#liquid-템플릿)
            * [Markdown 템플릿](#markdown-템플릿)
            * [Textile 템플릿](#textile-템플릿)
            * [RDoc 템플릿](#rdoc-템플릿)
            * [AsciiDoc 템플릿](#asciidoc-템플릿)
            * [Radius 템플릿](#radius-템플릿)
            * [Markaby 템플릿](#markaby-템플릿)
            * [RABL 템플릿](#rabl-템플릿)
            * [Slim 템플릿](#slim-템플릿)
            * [Creole 템플릿](#creole-템플릿)
            * [MediaWiki 템플릿](#mediawiki-템플릿)
            * [CoffeeScript 템플릿](#coffeescript-템플릿)
            * [Stylus 템플릿](#stylus-템플릿)
            * [Yajl 템플릿](#yajl-템플릿)
            * [WLang 템플릿](#wlang-템플릿)
        * [템플릿에서 변수에 접근하기](#템플릿에서-변수에-접근하기)
        * [템플릿에서의 `yield` 와 중첩 레이아웃](#템플릿에서의-yield-와-중첩-레이아웃)
        * [인라인 템플릿](#인라인-템플릿)
        * [이름을 가지는 템플릿(Named Templates)](#이름을-가지는-템플릿named-templates)
        * [파일 확장자 연결하기](#파일-확장자-연결하기)
        * [나만의 고유한 템플릿 엔진 추가하기](#나만의-고유한-템플릿-엔진-추가하기)
        * [템플릿 검사를 위한 커스텀 로직 사용하기](#템플릿-검사를-위한-커스텀-로직-사용하기)
    * [필터(Filters)](#필터filters)
    * [헬퍼(Helpers)](#헬퍼helpers)
        * [세션(Sessions) 사용하기](#세션sessions-사용하기)
        * [중단하기(Halting)](#중단하기halting)
        * [넘기기(Passing)](#넘기기passing)
        * [다른 라우터 부르기(Triggering Another Route)](#다른-라우터-부르기triggering-another-route)
        * [본문, 상태 코드 및 헤더 설정하기](#본문-상태-코드-및-헤더-설정하기)
        * [응답 스트리밍(Streaming Responses)](#응답-스트리밍streaming-responses)
        * [로깅(Logging)](#로깅logging)
        * [마임 타입(Mime Types)](#마임-타입mime-types)
        * [URL 생성하기](#url-생성하기)
        * [브라우저 재지정(Browser Redirect)](#브라우저-재지정browser-redirect)
        * [캐시 컨트롤(Cache Control)](#캐시-컨트롤cache-control)
        * [파일 전송하기(Sending Files)](#파일-전송하기sending-files)
        * [요청 객체에 접근하기(Accessing the Request Object)](#요청-객체에-접근하기accessing-the-request-object)
        * [첨부(Attachments)](#첨부attachments)
        * [날짜와 시간 다루기](#날짜와-시간-다루기)
        * [템플릿 파일 참조하기](#템플릿-파일-참조하기)
    * [설정(Configuration)](#설정configuration)
        * [공격 방어 설정하기(Configuring attack protection)](#공격-방어-설정하기configuring-attack-protection)
        * [가능한 설정들(Available Settings)](#가능한-설정들available-settings)
    * [환경(Environments)](#환경environments)
    * [에러 처리(Error Handling)](#에러-처리error-handling)
        * [찾을 수 없음(Not Found)](#찾을-수-없음not-found)
        * [에러](#에러)
    * [Rack 미들웨어(Rack Middleware)](#rack-미들웨어rack-middleware)
    * [테스팅(Testing)](#테스팅testing)
    * [Sinatra::Base - 미들웨어(Middleware), 라이브러리(Libraries), 그리고 모듈 앱(Modular Apps)](#sinatrabase---미들웨어middleware-라이브러리libraries-그리고-모듈-앱modular-apps)
        * [모듈(Modular) vs. 전통적 방식(Classic Style)](#모듈modular-vs-전통적-방식classic-style)
        * [모듈 애플리케이션(Modular Application) 제공하기](#모듈-애플리케이션modular-application-제공하기)
        * [config.ru로 전통적 방식의 애플리케이션 사용하기](#configru로-전통적-방식의-애플리케이션-사용하기)
        * [언제 config.ru를 사용할까?](#언제-configru를-사용할까)
        * [Sinatra를 미들웨어로 사용하기](#sinatra를-미들웨어로-사용하기)
        * [동적인 애플리케이션 생성(Dynamic Application Creation)](#동적인-애플리케이션-생성dynamic-application-creation)
    * [범위(Scopes)와 바인딩(Binding)](#범위scopes와-바인딩binding)
        * [애플리케이션/클래스 범위](#애플리케이션클래스-범위)
        * [요청/인스턴스 범위](#요청인스턴스-범위)
        * [위임 범위(Delegation Scope)](#위임-범위delegation-scope)
    * [명령행(Command Line)](#명령행command-line)
        * [다중 스레드(Multi-threading)](#다중-스레드multi-threading)
    * [요구사항(Requirement)](#요구사항requirement)
    * [최신(The Bleeding Edge)](#최신the-bleeding-edge)
        * [Bundler를 사용하여](#bundler를-사용하여)
        * [직접 하기(Roll Your Own)](#직접-하기roll-your-own)
        * [전역으로 설치(Install Globally)](#전역으로-설치install-globally)
    * [버저닝(Versioning)](#버저닝versioning)
    * [더 읽을 거리(Further Reading)](#더-읽을-거리further-reading)

## 라우터(Routes)

Sinatra에서, 라우터(route)는 URL-매칭 패턴과 쌍을 이루는 HTTP 메서드입니다.
각각의 라우터는 블록과 연결됩니다.

```ruby
get '/' do
  .. 무언가 보여주기(show) ..
end

post '/' do
  .. 무언가 만들기(create) ..
end

put '/' do
  .. 무언가 대체하기(replace) ..
end

patch '/' do
  .. 무언가 수정하기(modify) ..
end

delete '/' do
  .. 무언가 없애기(annihilate) ..
end

options '/' do
  .. 무언가 주기(appease) ..
end

link '/' do
  .. 무언가 관계맺기(affiliate) ..
end

unlink '/' do
  .. 무언가 격리하기(separate) ..
end
```

라우터는 정의된 순서에 따라 매치되고 요청에 대해 가장 먼저 매칭된 라우터가 호출됩니다.

라우터 패턴에는 이름을 가진 매개변수가 포함될 수 있으며, `params` 해시로 접근할 수 있습니다.

```ruby
get '/hello/:name' do
  # "GET /hello/foo" 및 "GET /hello/bar"와 매치
  # params['name']은 'foo' 또는 'bar'
  "Hello #{params['name']}!"
end
```

또한 블록 매개변수를 통하여도 이름을 가진 매개변수에 접근할 수 있습니다.

```ruby
get '/hello/:name' do |n|
  # "GET /hello/foo" 및 "GET /hello/bar"와 매치
  # params['name']은 'foo' 또는 'bar'
  # n 에는 params['name']가 저장
  "Hello #{n}!"
end
```

라우터 패턴에는 스플랫(splat, 또는 와일드카드)도 매개변수도 포함될 수 있으며, 이럴 경우 `params['splat']` 배열을 통해 접근할 수 있습니다.

```ruby
get '/say/*/to/*' do
  # /say/hello/to/world와 매치
  params['splat'] # => ["hello", "world"]
end

get '/download/*.*' do
  # /download/path/to/file.xml과 매치
  params['splat'] # => ["path/to/file", "xml"]
end
```

블록 매개변수로도 접근할 수 있습니다.

```ruby
get '/download/*.*' do |path, ext|
  [path, ext] # => ["path/to/file", "xml"]
end
```

라우터는 정규표현식으로 매치할 수 있습니다.

```ruby
get /\A\/hello\/([\w]+)\z/ do
  "Hello, #{params['captures'].first}!"
end
```

블록 매개변수로도 사용가능합니다.

```ruby
get %r{/hello/([\w]+)} do |c|
  # "GET /meta/hello/world", "GET /hello/world/1234" 등과 매치
  "Hello, #{c}!"
end
```

라우터 패턴에는 선택적인(optional) 매개변수도 올 수 있습니다.

```ruby
get '/posts/:format?' do
  # "GET /posts/" 는 물론 "GET /posts/json", "GET /posts/xml" 와 같은 어떤 확장자와도 매칭
end
```

쿼리 파라메터로도 이용가능 합니다.

```ruby
get '/posts' do
  # matches "GET /posts?title=foo&author=bar"
  title = params['title']
  author = params['author']
  # uses title and author variables; query is optional to the /posts route
end
```

한편, 경로 탐색 공격 방지(path traversal attack protection, 아래 참조)를 비활성화시키지 않았다면,
요청 경로는 라우터와 매칭되기 이전에 수정될 수 있습니다.

### 조건(Conditions)

라우터는 사용자 에이전트(user agent)같은 다양한 매칭 조건을 포함할 수 있습니다.

```ruby
get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
  "Songbird 버전 #{params['agent'][0]}을 사용하는군요!"
end

get '/foo' do
  # songbird 브라우저가 아닌 경우 매치
end
```

다른 가능한 조건에는 `host_name`과 `provides`가 있습니다.

```ruby
get '/', :host_name => /^admin\./ do
  "Admin Area, Access denied!"
end

get '/', :provides => 'html' do
  haml :index
end

get '/', :provides => ['rss', 'atom', 'xml'] do
  builder :feed
end
```
`provides`는 request의 허용된 해더를 검색합니다.

사용자 정의 조건도 쉽게 만들 수 있습니다.

```ruby
set(:probability) { |value| condition { rand <= value } }

get '/win_a_car', :probability => 0.1 do
  "내가 졌소!"
end

get '/win_a_car' do
  "미안해서 어쩌나."
end
```

여러 값을 받는 조건에는 스플랫(splat)을 사용합니다.

```ruby
set(:auth) do |*roles|   # <- 이게 스플랫
  condition do
    unless logged_in? && roles.any? {|role| current_user.in_role? role }
      redirect "/login/", 303
    end
  end
end

get "/my/account/", :auth => [:user, :admin] do
  "내 계정 정보"
end

get "/only/admin/", :auth => :admin do
  "관리자 외 접근불가!"
end
```

### 반환값(Return Values)

라우터 블록의 반환 값은 HTTP 클라이언트로 전달되는 응답 본문만을 결정하거나, 또는 Rack 스택에서 다음 번 미들웨어만를 결정합니다.
위의 예제에서 볼 수 있지만 대부분의 경우 이 반환값은 문자열입니다.하지만 다른 값도 허용됩니다.

유효한 Rack 응답, Rack 본문 객체 또는 HTTP 상태 코드가 되는 어떠한 객체라도 반환할 수 있습니다.

* 세 요소를 가진 배열: `[상태 (Fixnum), 헤더 (Hash), 응답 본문 (#each에 반응)]`
* 두 요소를 가진 배열: `[상태 (Fixnum), 응답 본문 (#each에 반응)]`
* `#each`에 반응하고 주어진 블록으로 문자열만을 전달하는 객체
* 상태 코드를 의미하는 Fixnum

이것을 이용한 예를 들자면, 스트리밍(streaming) 예제를 쉽게 구현할 수 있습니다.

```ruby
class Stream
  def each
100.times { |i| yield "#{i}\n" }
  end
end

get('/') { Stream.new }
```

`stream` 헬퍼 메서드(아래 참조)를 사용하면 이런 번거로움을 줄이고 스트리밍 로직을 라우터 속에 포함 시킬 수도 있습니다.

### 커스텀 라우터 매처(Custom Route Matchers)

위에서 보듯, Sinatra에는 문자열 패턴 및 정규표현식을 이용한 라우터 매칭 지원이 내장되어 있습니다.
하지만, 그게 끝은 아닙니다. 여러분 만의 매처(matcher)도 쉽게 정의할 수 있습니다.

```ruby
class AllButPattern
  Match = Struct.new(:captures)

  def initialize(except)
    @except   = except
    @captures = Match.new([])
  end

  def match(str)
    @captures unless @except === str
  end
end

def all_but(pattern)
  AllButPattern.new(pattern)
end

get all_but("/index") do
  # ...
end
```

사실 위의 예제는 조금 과하게 작성된 면이 있습니다. 간단하게 표현할 수도 있어요.

```ruby
get // do
  pass if request.path_info == "/index"
  # ...
end
```

또는 거꾸로 탐색(negative look ahead)할 수도 있습니다.

```ruby
get %r{^(?!/index$)} do
  # ...
end
```

## 정적 파일(Static Files)

정적 파일들은 `./public` 디렉터리에서 제공됩니다. 위치를 다른 곳으로
변경하려면 `:public_folder` 옵션을 지정하면 됩니다.

```ruby
set :public_folder, File.dirname(__FILE__) + '/static'
```

public 디렉터리명은 URL에 포함되지 않는다는 점에 주의하세요.
`./public/css/style.css` 파일은 아마 `http://example.com/css/style.css` 로 접근할 수 있을 것입니다.

`Cache-Control` 헤더 정보를 추가하려면 `:static_cache_control` 설정(아래 참조)을 사용하면 됩니다.

## 뷰 / 템플릿(Views / Templates)

템플릿 언어들은 각각의 렌더링 메서드를 통해 표출됩니다.
이들 메서드는 문자열을 반환할 뿐입니다.

```ruby
get '/' do
  erb :index
end
```

이 구문은 `views/index.erb`를 렌더합니다.

템플릿 이름 대신 템플릿의 내용을 직접 넘길 수도 있습니다.

```ruby
get '/' do
  code = "<%= Time.now %>"
  erb code
end
```

템플릿은 두 번째 인자로 옵션값의 해시를 받습니다.

```ruby
get '/' do
  erb :index, :layout => :post
end
```

이 구문은 `views/post.erb` 속에 내장된 `views/index.erb`를 렌더합니다.
(`views/layout.erb`파일이 존재할 경우 기본값은 `views/layout.erb`입니다.)

Sinatra가 이해하지 못하는 모든 옵션값들은 템플릿 엔진으로 전달됩니다.

```ruby
get '/' do
  haml :index, :format => :html5
end
```

옵션값은 템플릿 언어별로 전역적으로 설정할 수도 있습니다.

```ruby
set :haml, :format => :html5

get '/' do
  haml :index
end
```

render 메서드에서 전달된 옵션값들은 `set`을 통해 설정한 옵션값보다 우선합니다.

가능한 옵션값들은 다음과 같습니다.

<dl>
  <dt>locals</dt>
  <dd>
    문서로 전달되는 local 목록. 파셜과 함께 사용하기 좋음.
    예제: <tt>erb "<%= foo %>", :locals => {:foo => "bar"}</tt>
  </dd>

  <dt>default_encoding</dt>
  <dd>
    불확실한 경우에 사용할 문자열 인코딩.
    기본값은 <tt>settings.default_encoding</tt>.
  </dd>

  <dt>views</dt>
  <dd>
    템플릿을 로드할 뷰 폴더.
    기본값은 <tt>settings.views</tt>.
  </dd>

  <dt>layout</dt>
  <dd>
    레이아웃을 사용할지 여부 (<tt>true</tt> 또는 <tt>false</tt>), 만약
    이 값이 심볼일 경우, 사용할 템플릿을 지정. 예제:
    <tt>erb :index, :layout => !request.xhr?</tt>
  </dd>

  <dt>content_type</dt>
  <dd>
    템플릿이 생성하는 Content-Type, 기본값은 템플릿 언어에 의존.
  </dd>

  <dt>scope</dt>
  <dd>
    템플릿을 렌더링하는 범위. 기본값은 어플리케이션 인스턴스.
    만약 이 값을 변경하면, 인스턴스 변수와 헬퍼 메서드들을 사용할 수 없게 됨.
  </dd>

  <dt>layout_engine</dt>
  <dd>
    레이아웃 렌더링에 사용할 템플릿 엔진. 레이아웃을 지원하지 않는 언어인 경우에 유용.
    기본값은 템플릿에서 사용하는 엔진. 예제: <tt>set :rdoc, :layout_engine => :erb</tt>
  </dd>
</dl>


템플릿은 `./views` 디렉터리에 있는 것으로 가정됩니다. 뷰 디렉터리를
다른 곳으로 하고 싶으시면 이렇게 하세요.

```ruby
set :views, settings.root + '/templates'
```

템플릿은 언제나 심볼로 참조되어야 한다는 것에 주의하세요.
템플릿이 하위 디렉터리에 위치한 경우(그럴 경우에는 `:'subdir/template'`을
사용)에도 예외는 없습니다. 반드시 심볼이어야 하는 이유는, 문자열을 넘기면
렌더링 메서드가 전달된 문자열을 직접 렌더하기 때문입니다.

### 리터럴 템플릿(Literal Templates)

```ruby
get '/' do
  haml '%div.title Hello World'
end
```

템플릿 문자열을 렌더합니다.

### 가능한 템플릿 언어들(Available Template Languages)

일부 언어는 여러 개의 구현이 있습니다. (스레드에 안전하게 thread-safe) 어느 구현을
사용할지 저정하려면, 먼저 require 하기만 하면 됩니다.

```ruby
require 'rdiscount' # or require 'bluecloth'
get('/') { markdown :index }
```

#### Haml 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://haml.info/">haml</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.haml</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>haml :index, :format => :html5</tt></td>
  </tr>
</table>

#### Erb 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://www.kuwata-lab.com/erubis/">erubis</a> 또는 erb (루비 속에 포함)</td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.erb</tt>, <tt>.rhtml</tt>, <tt>.erubis</tt> (Erubis만 해당)</td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>erb :index</tt></td>
  </tr>
</table>

#### Builder 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="https://github.com/jimweirich/builder">builder</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.builder</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>builder { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

인라인 템플릿으로 블록을 받을 수도 있습니다(예제 참조).

#### Nokogiri 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://www.nokogiri.org/">nokogiri</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.nokogiri</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>nokogiri { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

인라인 템플릿으로 블록을 받을 수도 있습니다(예제 참조).

#### Sass 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://sass-lang.com/">sass</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.sass</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>sass :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

#### SCSS 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://sass-lang.com/">sass</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.scss</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>scss :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

#### Less 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://lesscss.org/">less</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.less</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>less :stylesheet</tt></td>
  </tr>
</table>

#### Liquid 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://liquidmarkup.org/">liquid</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.liquid</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>liquid :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

Liquid 템플릿에서는 루비 메서드(`yield` 제외)를 호출할 수 없기
때문에, 거의 대부분의 경우 locals를 전달해야 합니다.

#### Markdown 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td>
      <a href="https://github.com/davidfstr/rdiscount" title="RDiscount">RDiscount</a>,
      <a href="https://github.com/vmg/redcarpet" title="RedCarpet">RedCarpet</a>,
      <a href="http://deveiate.org/projects/BlueCloth" title="BlueCloth">BlueCloth</a>,
      <a href="http://kramdown.gettalong.org/" title="kramdown">kramdown</a>,
      <a href="https://github.com/bhollis/maruku" title="maruku">maruku</a>
      중 아무거나
    </td>
  </tr>
  <tr>
    <td>파일 확장</td>
    <td><tt>.markdown</tt>, <tt>.mkd</tt>,  <tt>.md</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>markdown :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

Markdown에서는 메서드 호출 뿐 아니라 locals 전달도 안됩니다.
따라서 일반적으로는 다른 렌더링 엔진과 함께 사용하게 됩니다.

```ruby
erb :overview, :locals => { :text => markdown(:introduction) }
```

다른 템플릿 속에서 `markdown` 메서드를 호출할 수도 있습니다.

```ruby
%h1 안녕 Haml!
%p= markdown(:greetings)
```

Markdown에서 루비를 호출할 수 없기 때문에, Markdown으로 작성된 레이아웃은
사용할 수 없습니다. 하지만, `:layout_engine` 옵션으로 레이아웃의 템플릿을
다른 렌더링 엔진으로 렌더링 할 수는 있습니다.

#### Textile 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://redcloth.org/">RedCloth</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.textile</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>textile :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

Textile에서는 메서드 호출 뿐 아니라 locals 전달도 안됩니다.
따라서 일반적으로는 다른 렌더링 엔진과 함께 사용하게 됩니다.

```ruby
erb :overview, :locals => { :text => textile(:introduction) }
```

다른 템플릿 속에서 `textile` 메서드를 호출할 수도 있습니다.

```ruby
%h1 안녕 Haml!
%p= textile(:greetings)
```

Textile에서 루비를 호출할 수 없기 때문에, Textile으로 작성된 레이아웃은
사용할 수 없습니다. 하지만, `:layout_engine` 옵션으로 레이아웃의 템플릿을
다른 렌더링 엔진으로 렌더링 할 수는 있습니다.

#### RDoc 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://rdoc.sourceforge.net/" title="RDoc">rdoc</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.rdoc</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>rdoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

RDoc에서는 메서드 호출 뿐 아니라 locals 전달도 안됩니다.
따라서 일반적으로는 다른 렌더링 엔진과 함께 사용하게 됩니다.

```ruby
erb :overview, :locals => { :text => rdoc(:introduction) }
```

다른 템플릿 속에서 `rdoc` 메서드를 호출할 수도 있습니다.

```ruby
%h1 Hello From Haml!
%p= rdoc(:greetings)
```

RDoc에서 루비를 호출할 수 없기 때문에, RDoc으로 작성된 레이아웃은
사용할 수 없습니다. 하지만, `:layout_engine` 옵션으로 레이아웃의 템플릿을
다른 렌더링 엔진으로 렌더링 할 수는 있습니다.

#### AsciiDoc 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://asciidoctor.org/" title="Asciidoctor">Asciidoctor</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.asciidoc</tt>, <tt>.adoc</tt> and <tt>.ad</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>asciidoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

AsciiDoc 템플릿에서는 루비 메서드를 호출할 수 없기
때문에, 거의 대부분의 경우 locals를 전달해야 합니다.

#### Radius 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="https://github.com/jlong/radius" title="Radius">radius</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.radius</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>radius :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

Radius 템플릿에서는 루비 메서드를 호출할 수 없기
때문에, 거의 대부분의 경우 locals를 전달해야 합니다.

#### Markaby 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://markaby.github.io/">markaby</a></td>
  </tr>
  <tr>
    <td>파일확장</td>
    <td><tt>.mab</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>markaby { h1 "Welcome!" }</tt></td>
  </tr>
</table>

인라인 템플릿으로 블록을 받을 수도 있습니다(예제 참조).

#### RABL 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="https://github.com/nesquena/rabl">rabl</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.rabl</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>rabl :index</tt></td>
  </tr>
</table>

#### Slim 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="http://slim-lang.com/">slim</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.slim</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>slim :index</tt></td>
  </tr>
</table>

#### Creole 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="https://github.com/minad/creole">creole</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.creole</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>creole :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

Creole에서는 메서드 호출 뿐 아니라 locals 전달도 안됩니다.
따라서 일반적으로는 다른 렌더링 엔진과 함께 사용하게 됩니다.

```ruby
erb :overview, :locals => { :text => creole(:introduction) }
```

다른 템플릿 속에서 `creole` 메서드를 호출할 수도 있습니다.

```ruby
%h1 Hello From Haml!
%p= creole(:greetings)
```

Creole에서 루비를 호출할 수 없기 때문에, Creole으로 작성된 레이아웃은
사용할 수 없습니다. 하지만, `:layout_engine` 옵션으로 레이아웃의 템플릿을
다른 렌더링 엔진으로 렌더링 할 수는 있습니다.

#### MediaWiki 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="https://github.com/nricciar/wikicloth" title="WikiCloth">WikiCloth</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.mediawiki</tt> and <tt>.mw</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>mediawiki :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

MediaWiki 마크업에서는 메서드 호출 뿐 아니라 locals 전달도 불가능합니다.
따라서 일반적으로는 다른 렌더링 엔진과 함께 사용하게 됩니다.

```ruby
erb :overview, :locals => { :text => mediawiki(:introduction) }
```

다른 템플릿 속에서 `mediawiki` 메서드를 호출할 수도 있습니다.

```ruby
%h1 Hello From Haml!
%p= mediawiki(:greetings)
```

MediaWiki에서 루비를 호출할 수 없기 때문에, MediaWiki으로 작성된 레이아웃은
사용할 수 없습니다. 하지만, `:layout_engine` 옵션으로 레이아웃의 템플릿을
다른 렌더링 엔진으로 렌더링 할 수는 있습니다.

#### CoffeeScript 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td>
      <a href="https://github.com/josh/ruby-coffee-script" title="Ruby CoffeeScript">
        CoffeeScript
      </a> 와
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        자바스크립트 실행법
      </a>
    </td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.coffee</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>coffee :index</tt></td>
  </tr>
</table>

#### Stylus 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td>
      <a href="https://github.com/forgecrafted/ruby-stylus" title="Ruby Stylus">
        Stylus
      </a> 와
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        자바스크립트 실행법
      </a>
    </td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.styl</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>stylus :index</tt></td>
  </tr>
</table>

Stylus 템플릿을 사용가능하게 하려면, 먼저 `stylus`와 `stylus/tilt`를 로드
해야합니다.

```ruby
require 'sinatra'
require 'stylus'
require 'stylus/tilt'

get '/' do
  stylus :example
end
```

#### Yajl 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="https://github.com/brianmario/yajl-ruby">yajl-ruby</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.yajl</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td>
      <tt>
        yajl :index,
             :locals => { :key => 'qux' },
             :callback => 'present',
             :variable => 'resource'
      </tt>
    </td>
  </tr>
</table>

템플릿 소스는 루비 문자열로 평가(evaluate)되고, 결과인 json 변수는 `#to_json`으로 변환됩니다.

```ruby
json = { :foo => 'bar' }
json[:baz] = key
```

`:callback`과 `:variable` 옵션은 렌더된 객체를 꾸미는데(decorate) 사용할 수 있습니다.

```javascript
var resource = {"foo":"bar","baz":"qux"};
present(resource);
```

#### WLang 템플릿

<table>
  <tr>
    <td>의존성</td>
    <td><a href="https://github.com/blambeau/wlang/" title="WLang">WLang</a></td>
  </tr>
  <tr>
    <td>파일 확장자</td>
    <td><tt>.wlang</tt></td>
  </tr>
  <tr>
    <td>예제</td>
    <td><tt>wlang :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

WLang 템플릿에서는 루비 메서드를 사용하는게 일반적이지 않기
때문에, 거의 대부분의 경우 locals를 전달합니다. 그래도
WLang으로 쓰여진 레이아웃과 `yield`는 지원합니다.

### 템플릿에서 변수에 접근하기

템플릿은 라우터 핸들러와 같은 맥락(context)에서 평가됩니다. 라우터
핸들러에서 설정한 인스턴스 변수들은 템플릿에서 직접 접근 가능합니다.

```ruby
get '/:id' do
  @foo = Foo.find(params['id'])
  haml '%h1= @foo.name'
end
```

명시적으로 로컬 변수의 해시를 지정할 수도 있습니다.

```ruby
get '/:id' do
  foo = Foo.find(params['id'])
  haml '%h1= bar.name', :locals => { :bar => foo }
end
```

이 방법은 주로 템플릿을 다른 템플릿 속에서 파셜(partial)로 렌더링할
때 사용됩니다.

### 템플릿에서의 `yield` 와 중첩 레이아웃

레이아웃은 보통 `yield`만 호출하는 템플릿입니다.
위에 설명된 `:template` 옵션을 통해 템플릿을 사용하거나,
다음 예제처럼 블록으로 렌더링 할 수 있습니다.

```ruby
erb :post, :layout => false do
  erb :index
end
```

위 코드는 `erb :index, :layout => :post`와 대부분 동일합니다.

렌더링 메서드에 블록 넘기기는 중첩 레이아웃을 만들때 유용합니다.

```ruby
erb :main_layout, :layout => false do
  erb :admin_layout do
    erb :user
  end
end
```

위의 코드도 줄일 수 있습니다.

```ruby
erb :admin_layout, :layout => :main_layout do
  erb :user
end
```

현재, `erb`, `haml`, `liquid`, `slim `, `wlang`는 블럭을 지원합니다.
일반적인 `render` 메소드도 블럭을 지원합니다.

### 인라인 템플릿

템플릿은 소스 파일의 마지막에서 정의할 수도 있습니다.

```ruby
require 'sinatra'

get '/' do
  haml :index
end

__END__

@@ layout
%html
= yield

@@ index
%div.title Hello world.
```

참고: sinatra를 require한 소스 파일에 정의된 인라인 템플릿은 자동으로
로드됩니다. 다른 소스 파일에서 인라인 템플릿을 사용하려면 명시적으로
`enable :inline_templates`을 호출하면 됩니다.

### 이름을 가지는 템플릿(Named Templates)

템플릿은 톱 레벨(top-level)에서 `template`메서드로도 정의할 수 있습니다.

```ruby
template :layout do
  "%html\n  =yield\n"
end

template :index do
  '%div.title Hello World!'
end

get '/' do
  haml :index
end
```

"layout"이라는 이름의 템플릿이 존재하면, 템플릿이 렌더될 때마다 사용됩니다.
레이아웃을 비활성화할 때는 `:layout => false`를 전달하여 개별적으로
비활성시키거나 `set :haml, :layout => false`으로 기본값을 비활성으로 둘 수
있습니다.

```ruby
get '/' do
  haml :index, :layout => !request.xhr?
end
```

### 파일 확장자 연결하기

어떤 파일 확장자를 특정 템플릿 엔진과 연결하려면, `Tilt.register`를 사용하면
됩니다. 예를 들어, `tt`라는 파일 확장자를 Textile 템플릿과 연결하고 싶다면,
다음과 같이 하면 됩니다.

```ruby
Tilt.register :tt, Tilt[:textile]
```

### 나만의 고유한 템플릿 엔진 추가하기

우선, Tilt로 여러분 엔진을 등록하고, 렌더링 메서드를 생성합니다.

```ruby
Tilt.register :myat, MyAwesomeTemplateEngine

helpers do
  def myat(*args) render(:myat, *args) end
end

get '/' do
  myat :index
end
```

위 코드는 `./views/index.myat` 를 렌더합니다.
Tilt에 대한 더 자세한 내용은 https://github.com/rtomayko/tilt 참조하세요.

### 템플릿 검사를 위한 커스텀 로직 사용하기

고유한 템플릿 룩업을 구현하기 위해서는 `#find_template` 메서드를 만드셔야 합니다.

```ruby
configure do
  set :views [ './views/a', './views/b' ]
end

def find_template(views, name, engine, &block)
  Array(views).each do |v|
    super(v, name, engine, &block)
  end
end
```

## 필터(Filters)

사전 필터(before filter)는 라우터와 동일한 맥락에서 매 요청 전에 평가되며
요청과 응답을 변형할 수 있습니다. 필터에서 설정된 인스턴스 변수들은 라우터와
템플릿에서 접근 가능합니다.

```ruby
before do
  @note = 'Hi!'
  request.path_info = '/foo/bar/baz'
end

get '/foo/*' do
  @note #=> 'Hi!'
  params['splat'] #=> 'bar/baz'
end
```

사후 필터(after filter)는 라우터와 동일한 맥락에서 매 요청 이후에 평가되며
마찬가지로 요청과 응답을 변형할 수 있습니다. 사전 필터와 라우터에서 설정된
인스턴스 변수들은 사후 필터에서 접근 가능합니다.

```ruby
after do
  puts response.status
end
```

참고: 만약 라우터에서 `body` 메서드를 사용하지 않고 그냥 문자열만 반환한
경우라면, body는 나중에 생성되는 탓에, 아직 사후 필터에서 사용할 수 없을
것입니다.

필터는 패턴을 취할 수도 있으며, 이 경우 요청 경로가 그 패턴과 매치할
경우에만 필터가 평가될 것입니다.

```ruby
before '/protected/*' do
  authenticate!
end

after '/create/:slug' do |slug|
  session['last_slug'] = slug
end
```

라우터와 마찬가지로, 필터 역시 조건을 취할 수 있습니다.

```ruby
before :agent => /Songbird/ do
  # ...
end

after '/blog/*', :host_name => 'example.com' do
  # ...
end
```

## 헬퍼(Helpers)

톱-레벨의 `helpers` 메서드를 사용하여 라우터 핸들러와 템플릿에서 사용할 헬퍼
메서드들을 정의할 수 있습니다.

```ruby
helpers do
  def bar(name)
    "#{name}bar"
  end
end

get '/:name' do
  bar(params['name'])
end
```

또는, 헬퍼 메서드는 별도의 모듈 속에 정의할 수도 있습니다.

```ruby
module FooUtils
  def foo(name) "#{name}foo" end
end

module BarUtils
  def bar(name) "#{name}bar" end
end

helpers FooUtils, BarUtils
```

이 것은 모듈을 애플리케이션 클래스에 포함(include)시킨 것과 같습니다.

### 세션(Sessions) 사용하기

세션은 요청 동안에 상태를 유지하기 위해 사용합니다.
세션이 활성화되면, 사용자 세션 당 세션 해시 하나씩을 갖게 됩니다.

```ruby
enable :sessions

get '/' do
  "value = " << session['value'].inspect
end

get '/:value' do
  session['value'] = params['value']
end
```

`enable :sessions`은 실은 모든 데이터를 쿠키 속에 저장하는 것에 주의하세요.
이 방식이 바람직하지 않을 수도 있습니다. (예를 들어, 많은 양의 데이터를
저장하게 되면 트래픽이 늘어납니다).
이런 경우에는 랙 세션 미들웨어(Rack session middleware)를 사용할 수 있습니다.
`enable :sessions`을 호출하지 **않는** 대신에, 선택한 미들웨어를 다른
미들웨어들처럼 포함시키면 됩니다.

```ruby
use Rack::Session::Pool, :expire_after => 2592000

get '/' do
  "value = " << session['value'].inspect
end

get '/:value' do
  session['value'] = params['value']
end
```

보안 강화을 위해서, 쿠키 속의 세션 데이터는 세션 시크릿(secret)으로
사인(sign)됩니다. Sinatra는 무작위 시크릿을 생성합니다. 하지만, 이
시크릿은 애플리케이션 시작 시마다 변경되기 때문에, 애플리케이션의
모든 인스턴스들이 공유할 시크릿을 직접 만들 수도 있습니다.

```ruby
set :session_secret, 'super secret'
```

조금 더 세부적인 설정이 필요하다면, `sessions` 설정에서 옵션이 있는
해시를 저장할 수도 있습니다.

```ruby
set :sessions, :domain => 'foo.com'
```

세션을 다른 foo.com의 서브도메인 들과 공유하기 원한다면, 다음에 나오는
것 처럼 도메인 앞에 *.*을 붙이셔야 합니다.

```ruby
set :sessions, :domain => '.foo.com'
```

### 중단하기(Halting)

필터나 라우터에서 요청을 즉각 중단하고 싶을 때 사용하합니다.

```ruby
halt
```

중단할 때 상태를 지정할 수도 있습니다.

```ruby
halt 410
```

본문을 넣을 수도 있습니다.

```ruby
halt 'this will be the body'
```

둘 다 할 수도 있습니다.

```ruby
halt 401, 'go away!'
```

헤더를 추가할 경우에는 다음과 같이 하면 됩니다.

```ruby
halt 402, {'Content-Type' => 'text/plain'}, 'revenge'
```

당연히 `halt`와 템플릿은 같이 사용할 수 있습니다.

```ruby
halt erb(:error)
```

### 넘기기(Passing)

라우터는 `pass`를 사용하여 다음 번 매칭되는 라우터로 처리를 넘길 수 있습니다.

```ruby
get '/guess/:who' do
  pass unless params['who'] == 'Frank'
  'You got me!'
end

get '/guess/*' do
  'You missed!'
end
```

이 때 라우터 블록에서 즉각 빠져나오게 되고 제어는 다음 번 매칭되는 라우터로
넘어갑니다. 만약 매칭되는 라우터를 찾지 못하면, 404가 반환됩니다.

### 다른 라우터 부르기(Triggering Another Route)

때로는 `pass`가 아니라, 다른 라우터를 호출한 결과를 얻고 싶을 때도
있습니다. 이럴때는 간단하게 `call`을 사용하면 됩니다.

```ruby
get '/foo' do
  status, headers, body = call env.merge("PATH_INFO" => '/bar')
  [status, headers, body.map(&:upcase)]
end

get '/bar' do
"bar"
end
```

위 예제의 경우, `"bar"`를 헬퍼로 옮겨 `/foo`와 `/bar` 모두에서 사용하도록
하면 테스팅을 쉽게 하고 성능을 높일 수 있습니다.

요청의 사본이 아닌 바로 그 인스턴스로 보내지도록 하고 싶다면,
`call` 대신 `call!`을 사용하면 됩니다.

`call`에 대한 더 자세한 내용은 Rack 명세를 참고하세요.

### 본문, 상태 코드 및 헤더 설정하기

라우터 블록의 반환값과 함께 상태 코드(status code)와 응답 본문(response body)을
설정할수 있고 권장됩니다. 하지만, 경우에 따라서는 본문을 실행 흐름 중의 임의
지점에서 설정해야 할때도 있습니다. 이런 경우 `body` 헬퍼 메서드를 사용하면
됩니다. 이렇게 하면, 그 순간부터 본문에 접근할 때 그 메서드를 사용할 수가 있습니다.

```ruby
get '/foo' do
  body "bar"
end

after do
  puts body
end
```

`body`로 블록을 전달하는 것도 가능하며, 이 블록은 랙(Rack) 핸들러에 의해
실행됩니다. (이 방법은 스트리밍을 구현할 때 사용할 수 있습니다. "값
반환하기"를 참고하세요).

본문와 마찬가지로, 상태코드와 헤더도 설정할 수 있습니다.

```ruby
get '/foo' do
  status 418
  headers \
"Allow"   => "BREW, POST, GET, PROPFIND, WHEN",
"Refresh" => "Refresh: 20; http://www.ietf.org/rfc/rfc2324.txt"
  body "I'm a tea pot!"
end
```

`body`처럼, `header`와 `status`도 매개변수 없이 사용하여 현재 값을
액세스할 수 있습니다.

### 응답 스트리밍(Streaming Responses)

응답 본문의 일정 부분을 계속 생성하는 가운데 데이터를 내보내기 시작하고
싶을 경우가 있습니다. 극단적인 예제로, 클라이언트가 접속을 끊기 전까지
계속 데이터를 내보내고 싶을 경우도 있죠. 여러분만의 래퍼(wrapper)를
만들지 않으려면 `stream` 헬퍼를 사용하면 됩니다.

```ruby
get '/' do
  stream do |out|
    out << "It's gonna be legen -\n"
    sleep 0.5
    out << " (wait for it) \n"
    sleep 1
    out << "- dary!\n"
  end
end
```

이렇게 스트리밍 API나 [서버 발송 이벤트Server Sent
Events](https://w3c.github.io/eventsource/)를 구현할 수 있고, 이 방법은
[WebSockets](https://en.wikipedia.org/wiki/WebSocket)을 위한 기반으로 사용됩니다.
이 방법은 일부 콘텐츠가 느린 자원에 의존하는 경우에 스로풋(throughtput)을
높이기 위해 사용되기도 합니다.

스트리밍 동작, 특히 동시 요청의 수는 애플리케이션을 서빙하는 웹서버에 크게
의존합니다.  일부의 경우 아예 스트리밍을 지원하지 조차 않습니다.  만약 서버가
스트리밍을 지원하지 않는다면, 본문은 `stream` 으로 전달된 블록이 수행을 마친
후에 한꺼번에 반환됩니다. 이런 한번에 쏘는 샷건같은 방식으로는 스트리밍은
움직이지 않습니다.

선택적 매개변수 `keep_open`이 설정되어 있다면, 스트림 객체에서 `close`를
호출하지 않을 것이고, 나중에 실행 흐름 상의 어느 시점에서 스트림을 닫을 수
있습니다. 이 옵션은 Thin과 Rainbow 같은 이벤트 기반 서버에서만 작동하고
다른 서버들은 여전히 스트림을 닫습니다.

```ruby
# long polling

set :server, :thin
connections = []

get '/subscribe' do
  # register a client's interest in server events
  stream(:keep_open) do |out|
    connections << out
    # purge dead connections
    connections.reject!(&:closed?)
  end
end

post '/:message' do
  connections.each do |out|
    # notify client that a new message has arrived
    out << params['message'] << "\n"

    # indicate client to connect again
    out.close
  end

  # acknowledge
  "message received"
end
```

### 로깅(Logging)

요청 스코프(request scope) 내에서, `Logger`의 인스턴스인 `logger`
헬퍼를 사용할 수 있습니다.

```ruby
get '/' do
  logger.info "loading data"
  # ...
end
```

이 로거는 자동으로 Rack 핸들러에서 설정한 로그설정을  참고합니다.
만약 로깅이 비활성상태라면, 이 메서드는 더미(dummy) 객체를 반환하기 때문에,
라우터나 필터에서 이 부분에 대해 걱정할 필요는 없습니다.

로깅은 `Sinatra::Application`에서만 기본으로 활성화되어 있음에 유의합시다.
만약 `Sinatra::Base`로부터 상속받은 경우라면 직접 활성화시켜 줘야 합니다.

```ruby
class MyApp < Sinatra::Base
  configure :production, :development do
    enable :logging
  end
end
```

로깅 미들웨어를 사용하지 않으려면, `logging` 설정을 `nil`로 두면 됩니다.
하지만, 이 경우 주의할 것은 `logger`는 `nil`을 반환하는 것입니다.
통상적인 유스케이스는 여러분만의 로거를 사용하고자 할 경우일 것입니다.
Sinatra는 `env['rack.logger']`에서 찾은 로거를 사용할 것입니다.

### 마임 타입(Mime Types)

`send_file`이나 정적인 파일을 사용할 때에 Sinatra가 인식하지 못하는
마임 타입이 있을 수 있습니다. 이 경우 `mime_type`을 사용하여 파일
확장자를 등록합니다.

```ruby
configure do
  mime_type :foo, 'text/foo'
end
```

`content_type` 헬퍼로 쓸 수도 있습니다.

```ruby
get '/' do
  content_type :foo
  "foo foo foo"
end
```

### URL 생성하기

URL을 생성할때 `url` 헬퍼 메서드를 사용합니다. 예를 들어 Haml에서는 이렇게
합니다.

```ruby
%a{:href => url('/foo')} foo
```

이것은 리버스 프록시(reverse proxies)와 Rack 라우터가 있다면 참고합니다.

이 메서드는 `to`라는 별칭으로도 사용할 수 있습니다. (아래 예제 참조)

### 브라우저 재지정(Browser Redirect)

`redirect` 헬퍼 메서드를 사용하여 브라우저를 리다이렉트 시킬 수 있습니다.

```ruby
get '/foo' do
  redirect to('/bar')
end
```

다른 부가적인 매개변수들은 `halt`에 전달하는 인자들과 비슷합니다.

```ruby
redirect to('/bar'), 303
redirect 'http://www.google.com/', 'wrong place, buddy'
```

`redirect back`을 사용하면 쉽게 사용자가 왔던 페이지로 다시 돌아가게
할 수 있습니다.

```ruby
get '/foo' do
  "<a href='/bar'>do something</a>"
end

get '/bar' do
  do_something
  redirect back
end
```

리다이렉트와 함께 인자를 전달하려면, 쿼리로 붙이거나,

```ruby
redirect to('/bar?sum=42')
```

세션을 사용하면 됩니다.

```ruby
enable :sessions

get '/foo' do
  session['secret'] = 'foo'
  redirect to('/bar')
end

get '/bar' do
  session['secret']
end
```

### 캐시 컨트롤(Cache Control)

헤더를 정확하게 설정하는 것은 적절한 HTTP 캐싱의 기본입니다.

Cache-Control 헤더를 다음과 같이 간단하게 설정할 수 있습니다.

```ruby
get '/' do
  cache_control :public
  "cache it!"
end
```

프로 팁: 캐싱은 사전 필터에서 설정하세요.

```ruby
before do
  cache_control :public, :must_revalidate, :max_age => 60
end
```

`expires` 헬퍼를 사용하여 그에 상응하는 헤더를 설정한다면,
`Cache-Control`이 자동으로 설정됩니다.

```ruby
before do
  expires 500, :public, :must_revalidate
end
```

캐시를 잘 사용하려면, `etag` 또는 `last_modified`을 사용해 보세요.
무거운 작업을 하기 *전*에 이들 헬퍼를 호출하길 권장합니다. 이렇게 하면,
클라이언트 캐시에 현재 버전이 이미 들어 있을 경우엔 즉각 응답을
뿌릴(flush) 것입니다.

```ruby
get "/article/:id" do
  @article = Article.find params['id']
  last_modified @article.updated_at
  etag @article.sha1
  erb :article
end
```

[약한 ETag](https://en.wikipedia.org/wiki/HTTP_ETag#Strong_and_weak_validation)를
사용할 수 도 있습니다.

```ruby
etag @article.sha1, :weak
```

이들 헬퍼는 어떠한 캐싱도 하지 않으며, 대신 캐시에 필요한 정보를 제공합니다.
손쉬운 리버스 프록시(reverse-proxy) 캐싱 솔루션을 찾고 있다면,
[rack-cache](https://github.com/rtomayko/rack-cache)를 써보세요.

```ruby
require "rack/cache"
require "sinatra"

use Rack::Cache

get '/' do
  cache_control :public, :max_age => 36000
  sleep 5
  "hello"
end
```

정적 파일에 `Cache-Control` 헤더 정보를 추가하려면 `:static_cache_control`
설정(아래 참조)을 쓰세요.

RFC 2616에 따르면 If-Match 또는 If-None-Match 헤더가 `*`로 설정된 경우 요청한
리소스(resource)가 이미 존재하느냐 여부에 따라 다르게 취급해야 한다고 되어
있습니다. Sinatra는 (get 처럼) 안전하거나 (put 처럼) 멱등인 요청에 대한 리소스는
이미 존재한다고 가정하지만, 다른 리소스(예를 들면 post 요청 같은)의 경우는
새 리소스로 취급합니다. 이 행동은 `:new_resource` 옵션을 전달하여 변경할 수 있습니다.

```ruby
get '/create' do
  etag '', :new_resource => true
  Article.create
  erb :new_article
end
```

약한 ETag를 사용하고자 한다면, `:kind`으로 전달합시다.

```ruby
etag '', :new_resource => true, :kind => :weak
```

### 파일 전송하기(Sending Files)

응답(response)으로 파일의 컨탠츠를 리턴하려면, `send_file` 헬퍼 메서드를 사용하면 됩니다.

```ruby
get '/' do
  send_file 'foo.png'
end
```

이 메서드는 몇 가지 옵션을 받습니다.

```ruby
send_file 'foo.png', :type => :jpg
```

옵션들:

<dl>
  <dt>filename</dt>
    <dd>응답에서 사용되는 파일명. 기본값은 실제 파일명.</dd>

  <dt>last_modified</dt>
    <dd>Last-Modified 헤더값. 기본값은 파일의 mtime.</dd>

  <dt>type</dt>
    <dd>Content-Type 헤더값. 없으면 파일 확장자로부터 유추.</dd>

  <dt>disposition</dt>
    <dd>
      Content-Disposition 헤더값. 가능한 값들: <tt>nil</tt> (기본값),
      <tt>:attachment</tt> 및 <tt>:inline</tt>
    </dd>

  <dt>length</dt>
    <dd>Content-Length 헤더값, 기본값은 파일 크기.</dd>

  <dt>status</dt>
    <dd>
      전송할 상태 코드. 오류 페이지로 정적 파일을 전송할 경우에 유용.

      Rack 핸들러가 지원할 경우, Ruby 프로세스로부터의 스트리밍이 아닌
      다른 수단이 사용가능함. 이 헬퍼 메서드를 사용하게 되면, Sinatra는
      자동으로 범위 요청(range request)을 처리함.
    </dd>
</dl>


### 요청 객체에 접근하기(Accessing the Request Object)

들어오는 요청 객에는 요청 레벨(필터, 라우터, 오류 핸들러)에서 `request`
메서드를 통해 접근 가능합니다.

```ruby
# http://example.com/example 상에서 실행 중인 앱
get '/foo' do
  t = %w[text/css text/html application/javascript]
  request.accept              # ['text/html', '*/*']
  request.accept? 'text/xml'  # true
  request.preferred_type(t)   # 'text/html'
  request.body                # 클라이언트로부터 전송된 요청 본문 (아래 참조)
  request.scheme              # "http"
  request.script_name         # "/example"
  request.path_info           # "/foo"
  request.port                # 80
  request.request_method      # "GET"
  request.query_string        # ""
  request.content_length      # request.body의 길이
  request.media_type          # request.body의 미디어 유형
  request.host                # "example.com"
  request.get?                # true (다른 동사에 대해 유사한 메서드 있음)
  request.form_data?          # false
  request["SOME_HEADER"]      # SOME_HEADER 헤더의 값
  request.referrer            # 클라이언트의 리퍼러 또는 '/'
  request.user_agent          # 사용자 에이전트 (:agent 조건에서 사용됨)
  request.cookies             # 브라우저 쿠키의 해시
  request.xhr?                # 이게 ajax 요청인가요?
  request.url                 # "http://example.com/example/foo"
  request.path                # "/example/foo"
  request.ip                  # 클라이언트 IP 주소
  request.secure?             # false (ssl 접속인 경우 true)
  request.forwarded?          # true (리버스 프록시 하에서 작동 중이라면)
  request.env                 # Rack에 의해 처리되는 로우(raw) env 해시
end
```

`script_name`, `path_info`같은 일부 옵션들은 이렇게 쓸 수도 있습니다.

```ruby
before { request.path_info = "/" }

get "/" do
  "all requests end up here"
end
```

`request.body`는 IO 객체이거나 StringIO 객체입니다.

```ruby
post "/api" do
  request.body.rewind  # 누군가 이미 읽은 경우
  data = JSON.parse request.body.read
  "Hello #{data['name']}!"
end
```

### 첨부(Attachments)

`attachment` 헬퍼를 사용하여 응답이 브라우저에 표시하는 대신
디스크에 저장되어야 함을 블라우저에게 알릴 수 있습니다.

```ruby
get '/' do
  attachment
  "store it!"
end
```

파일명을 전달할 수도 있습니다.

```ruby
get '/' do
  attachment "info.txt"
  "store it!"
end
```

### 날짜와 시간 다루기

Sinatra는 `time_for_` 헬퍼 메서드를 제공합니다. 이 메서드는
주어진 값으로부터 Time 객체를 생성한다. `DateTime`, `Date` 같은
비슷한 클래스들도 변환됩니다.

```ruby
get '/' do
  pass if Time.now > time_for('Dec 23, 2012')
  "still time"
end
```

이 메서드는 내부적으로 `expires` 나 `last_modified` 같은 곳에서 사용됩니다.
따라서 여러분은 애플리케이션에서 `time_for`를 오버라이딩하여 이들 메서드의
동작을 쉽게 확장할 수 있습니다.

```ruby
helpers do
  def time_for(value)
    case value
    when :yesterday then Time.now - 24*60*60
    when :tomorrow  then Time.now + 24*60*60
    else super
    end
  end
end

get '/' do
  last_modified :yesterday
  expires :tomorrow
  "hello"
end
```

### 템플릿 파일 참조하기

`find_template`는 렌더링할 템플릿 파일을 찾는데 사용됩니다.

```ruby
find_template settings.views, 'foo', Tilt[:haml] do |file|
  puts "could be #{file}"
end
```

이것만으로는 그렇게 유용하지는 않습니다만, 이 메서드를 오버라이드하여 여러분만의
참조 메커니즘에서 가로채게 하면 유용해집니다. 예를 들어, 하나 이상의 뷰 디렉터리를
사용하고자 한다면 이렇게 하세요.

```ruby
set :views, ['views', 'templates']

helpers do
  def find_template(views, name, engine, &block)
    Array(views).each { |v| super(v, name, engine, &block) }
  end
end
```

다른 예제는 각 엔진마다 다른 디렉터리를 사용할 경우입니다.

```ruby
set :views, :sass => 'views/sass', :haml => 'templates', :default => 'views'

helpers do
  def find_template(views, name, engine, &block)
    _, folder = views.detect { |k,v| engine == Tilt[k] }
    folder ||= views[:default]
    super(folder, name, engine, &block)
  end
end
```

여러분은 이것을 간단하게 확장(extension)으로 만들어 다른 사람들과 공유할 수 있다!

`find_template`은 그 파일이 실제 존재하는지 검사하지 않음에 유의합니다.
모든 가능한 경로에 대해 주어진 블록을 호출할 뿐입니다. 이것은 성능 문제는
되지 않습니다. 왜냐하면 `render`는 파일이 발견되는 즉시 `break`하기 때문입니다.
또한, 템플릿 위치(그리고 콘텐츠)는 개발 모드에서 실행 중이 아니라면 캐시될 것입니다.
정말로 멋진 메세드를 작성하고 싶다면 이 점을 명심하세요.

## 설정(Configuration)

모든 환경에서, 시작될 때, 한번만 실행되게 하려면 이렇게 하면 됩니다.

```ruby
configure do
  # 옵션 하나 설정
  set :option, 'value'

  # 여러 옵션 설정
  set :a => 1, :b => 2

  # `set :option, true`와 동일
  enable :option

  # `set :option, false`와 동일
  disable :option

  # 블록으로 동적인 설정을 할 수도 있음
  set(:css_dir) { File.join(views, 'css') }
end
```

환경(RACK_ENV 환경 변수)이 `:production`일 때만 실행되게 하려면 이렇게 하면 됩니다.

```ruby
configure :production do
  ...
end
```

환경이 `:production` 또는 `:test`일 때 실행되게 하려면 이렇게 하면 됩니다.

```ruby
configure :production, :test do
  ...
end
```

이 옵션들은 `settings`를 통해 접근 가능합니다.

```ruby
configure do
  set :foo, 'bar'
end

get '/' do
  settings.foo? # => true
  settings.foo  # => 'bar'
  ...
end
```

### 공격 방어 설정하기(Configuring attack protection)

Sinatra는 [Rack::Protection](https://github.com/sinatra/rack-protection#readme)을 사용하여
일반적이고 일어날 수 있는 공격에 대비합니다. 이 모듈은 간단하게 비활성시킬 수 있습니다.
(하지만 애플리케이션에 엄청나게 많은 취약성을 야기합니다.)

```ruby
disable :protection
```

하나의 방어층만 스킵하려면, 옵션 해시에 `protection`을 설정하면 됩니다.

```ruby
set :protection, :except => :path_traversal
```

배열로 넘김으로써 방어층 여러 개를 비활성화할 수 있습니다.

```ruby
set :protection, :except => [:path_traversal, :session_hijacking]
```

기본적으로 `:sessions`가 활성 중일 때만 Sinatra는 방어층을 설정합니다.
때로는 자신만의 세션을 설정할 때도 있습니다. 이런 경우 `:session` 옵션을
넘겨줌으로써 세션을 기반으로한 방어층을 설정 할 수 있습니다.

```ruby
use Rack::Session::Pool
set :protection, :session => true
```

### 가능한 설정들(Available Settings)

<dl>
  <dt>absolute_redirects</dt>
  <dd>
    만약 비활성이면, Sinatra는 상대경로 리다이렉트를 허용할 것이지만,
    이렇게 되면 Sinatra는 더 이상 오직 절대경로 리다이렉트만 허용하고 있는
    RFC 2616(HTTP 1.1)에 위배됨.
  </dd>
  <dd>
    적정하게 설정되지 않은 리버스 프록시 하에서 앱을 실행 중이라면 활성화시킬 것.
    <tt>rul</tt> 헬퍼는, 만약 두 번째 매개변수로 <tt>false</tt>를 전달하지만 않는다면,
    여전히 절대경로 URL을 생성할 것임에 유의.
  </dd>
  <dd>기본값은 비활성.</dd>

  <dt>add_charset</dt>
  <dd>
    <tt>content_type</tt>가 문자셋 정보에 자동으로 추가하게 될 마임(mime) 타입.
     이 옵션은 오버라이딩하지 말고 추가해야 함.
    <tt>settings.add_charset << "application/foobar"</tt>
  </dd>

  <dt>app_file</dt>
  <dd>
    메인 애플리케이션 파일의 경로. 프로젝트 루트, 뷰, public 폴더,
    인라인 템플릿을 파악할 때 사용됨.
  </dd>

  <dt>bind</dt>
  <dd>바인드할 IP 주소(기본값: <tt>0.0.0.0</tt> <em>이나</em>
  `environment`가 개발로 설정 되어있으면 <tt>localhost</tt>). 오직
  빌트인(built-in) 서버에서만 사용됨.</dd>

  <dt>default_encoding</dt>
  <dd>인코딩을 알 수 없을 때 인코딩(기본값은 <tt>"utf-8"</tt>).</dd>

  <dt>dump_errors</dt>
  <dd>로그안의 에러 출력.</dd>

  <dt>environment</dt>
  <dd>
    현재 환경, 기본값은 <tt>ENV['RACK_ENV']</tt> ENV에 없을 경우엔 "development".
  </dd>

  <dt>logging</dt>
  <dd>로거(logger) 사용.</dd>

  <dt>lock</dt>
  <dd>
    Ruby 프로세스 당 요청을 동시에 할 경우에만 매 요청에 걸쳐 잠금(lock)을 설정.
  </dd>
  <dd>앱이 스레드에 안전(thread-safe)하지 않으면 활성화시킬 것. 기본값은 비활성.</dd>

  <dt>method_override</dt>
  <dd>
    put/delete를 지원하지 않는 브라우저에서 put/delete 폼을 허용하는
    <tt>_method</tt> 꼼수 사용.
  </dd>

  <dt>port</dt>
  <dd>접속 포트. 빌트인 서버에서만 사용됨.</dd>

  <dt>prefixed_redirects</dt>
  <dd>
    절대경로가 주어지지 않은 리다이렉트에 <tt>request.script_name</tt>를
    삽입할지 여부를 결정. 활성화 하면 <tt>redirect '/foo'</tt>는
    <tt>redirect to('/foo')</tt>처럼 동작. 기본값은 비활성.
  </dd>

  <dt>protection</dt>
  <dd>웹 공격 방어를 활성화시킬 건지 여부. 위의 보안 섹션 참조.</dd>

  <dt>public_dir</dt>
  <dd><tt>public_folder</tt>의 별칭. 밑을 참조.</dd>

  <dt>public_folder</dt>
  <dd>
    public 파일이 제공될 폴더의 경로.
    static 파일 제공이 활성화된 경우만 사용됨(아래 <tt>static</tt>참조).
    만약 설정이 없으면 <tt>app_file</tt>로부터 유추됨.
  </dd>

  <dt>reload_templates</dt>
  <dd>
    요청 간에 템플릿을 리로드(reload)할 건지 여부. 개발 모드에서는 활성됨.
  </dd>

  <dt>root</dt>
  <dd>
    프로젝트 루트 디렉터리 경로. 설정이 없으면 <tt>app_file</tt> 설정으로부터 유추됨.
  </dd>

  <dt>raise_errors</dt>
  <dd>
    예외 발생(애플리케이션은 중단됨).
    기본값은 <tt>environment</tt>가 <tt>"test"</tt>인 경우는 활성, 그렇지 않으면 비활성.
  </dd>

  <dt>run</dt>
  <dd>
    활성화되면, Sinatra가 웹서버의 시작을 핸들링.
    rackup 또는 다른 도구를 사용하는 경우라면 활성화시키지 말 것.
  </dd>

  <dt>running</dt>
  <dd>빌트인 서버가 실행 중인가? 이 설정은 변경하지 말 것!</dd>

  <dt>server</dt>
  <dd>
    빌트인 서버로 사용할 서버 또는 서버 목록.
    기본값은 루비구현에 따라 다르며 순서는 우선순위를 의미.
  </dd>

  <dt>sessions</dt>
  <dd>
    <tt>Rack::Session::Cookie</tt>를 사용한 쿠키 기반 세션 활성화.
    보다 자세한 정보는 '세션 사용하기' 참조.
  </dd>

  <dt>show_exceptions</dt>
  <dd>
    예외 발생 시에 브라우저에 스택 추적을 보임.
    기본값은 <tt>environment</tt>가 <tt>"development"</tt>인
    경우는 활성, 나머지는 비활성.
  </dd>
  <dd>
    <tt>:after_handler</tt>를 설정함으로써 브라우저에서
    스택 트레이스를 보여주기 전에 앱에 특화된 에러 핸들링을
    할 수도 있음.
  </dd>

  <dt>static</dt>
  <dd>Sinatra가 정적(static) 파일을 핸들링할 지 여부를 설정.</dd>
  <dd>이 기능이 가능한 서버를 사용하는 경우라면 비활성시킬 것.</dd>
  <dd>비활성시키면 성능이 올라감.</dd>
  <dd>
    기본값은 전통적 방식에서는 활성, 모듈 앱에서는 비활성.
  </dd>

  <dt>static_cache_control</dt>
  <dd>
    Sinatra가 정적 파일을 제공하는 경우, 응답에 <tt>Cache-Control</tt> 헤더를
    추가할 때 설정. <tt>cache_control</tt> 헬퍼를 사용.
    기본값은 비활성.
  </dd>
  <dd>
    여러 값을 설정할 경우는 명시적으로 배열을 사용할 것:
    <tt>set :static_cache_control, [:public, :max_age => 300]</tt>
  </dd>

  <dt>threaded</dt>
  <dd>
    <tt>true</tt>로 설정하면, Thin이 요청을 처리하는데 있어
    <tt>EventMachine.defer</tt>를 사용하도록 함.
  </dd>

  <dt>views</dt>
  <dd>
    뷰 폴더 경로. 설정하지 않은 경우 <tt>app_file</tt>로부터 유추됨.
  </dd>

  <dt>x_cascade</dt>
  <dd>
    라우트를 찾지못했을 때의 X-Cascade 해더를 설정여부.
    기본값은 <tt>true</tt>
  </dd>
</dl>


## 환경(Environments)

3가지의 미리 정의된 `environments` `"development"`, `"production"`, `"test"`
가 있습니다. 환경은 `RACK_ENV` 환경 변수를 통해서도 설정됩니다. 기본값은
`"development"`입니다. `"development"` 모드에서는 모든 템플릿들은 요청 간에
리로드됩니다. 또, `"development"` 모드에서는 특별한 `not_found` 와 `error`
핸들러가 브라우저에서 스택 트레이스를 볼 수 있게합니다.
`"production"`과 `"test"`에서는 기본적으로 템플릿은 캐시됩니다.

다른 환경으로 실행시키려면 `RACK_ENV` 환경 변수를 사용하세요.

```shell
RACK_ENV=production ruby my_app.rb
```

현재 설정된 환경이 무엇인지 검사하기 위해서는 준비된 `development?`, `test?`,
`production?` 메서드를 사용할 수 있습니다.

```ruby
get '/' do
  if settings.development?
    "development!"
  else
    "not development!"
  end
end
```

## 에러 처리(Error Handling)

예외 핸들러는 라우터 및 사전 필터와 동일한 맥락에서 실행됩니다.
이 말인즉, `haml`, `erb`, `halt`같은 이들이 제공하는 모든  것들을 사용할 수
있다는 뜻입니다.

### 찾을 수 없음(Not Found)

`Sinatra::NotFound` 예외가 발생하거나 또는 응답의 상태 코드가 404라면,
`not_found` 핸들러가 호출됩니다.

```ruby
not_found do
  '아무 곳에도 찾을 수 없습니다.'
end
```

### 에러

`error` 핸들러는 라우터 또는 필터에서 뭐든 오류가 발생할 경우에 호출됩니다.
하지만 개발 환경에서는 예외 확인 옵션을 `:after_handler`로 설정되어 있을 경우에만
실행됨을 주의하세요.

```ruby
set :show_exceptions, :after_handler
```

예외 객체는 Rack 변수 `sinatra.error`로부터 얻을 수 있습니다.

```ruby
error do
  '고약한 오류가 발생했군요 - ' + env['sinatra.error'].message
end
```

사용자 정의 오류는 이렇게 정의합니다.

```ruby
error MyCustomError do
  '무슨 일이 생겼나면요...' + env['sinatra.error'].message
end
```

그런 다음, 이 오류가 발생하면 이렇게 처리합니다.

```ruby
get '/' do
  raise MyCustomError, '안좋은 일'
end
```

결과는 이렇습니다.

```
무슨 일이 생겼냐면요... 안좋은 일
```

상태 코드에 대해 오류 핸들러를 설치할 수도 있습니다.

```ruby
error 403 do
  '액세스가 금지됨'
end

get '/secret' do
  403
end
```

범위로 지정할 수도 있습니다.

```ruby
error 400..510 do
  '어이쿠'
end
```

Sinatra는 개발 환경에서 동작할 때 브라우저에 괜찮은 스택 트레이스와 추가적인
디버그 정보를 보여주기 위해 특별한 `not_found` 와 `error` 핸들러를 설치합니다.

## Rack 미들웨어(Middleware)

Sinatra는 [Rack](http://rack.github.io/) 위에서 동작하며, Rack은 루비 웹
프레임워크를 위한 최소한의 표준 인터페이스입니다. Rack이 애플리케이션 개발자들에게
제공하는 가장 흥미로운 기능은 "미들웨어(middleware)"에 대한 지원입니다.
여기서 미들웨어란 서버와 여러분의 애플리케이션 사이에 위치하면서 HTTP 요청/응답을
모니터링하거나/조작함으로써 다양한 유형의 공통 기능을 제공하는 컴포넌트입니다.

Sinatra는 톱레벨의 `use` 메서드를 사용하여 Rack 미들웨어의 파이프라인을 만드는 일을
식은 죽 먹기로 만듭니다.

```ruby
require 'sinatra'
require 'my_custom_middleware'

use Rack::Lint
use MyCustomMiddleware

get '/hello' do
  'Hello World'
end
```

`use`문법은 [Rack::Builder](http://www.rubydoc.info/github/rack/rack/master/Rack/Builder) DSL
(rackup 파일에서 가장 많이 사용)에서 정의한 것과 동일합니다. 예를 들어, `use` 메서드는
블록이나 여러 개의/가변적인 인자도 받을 수 있습니다.

```ruby
use Rack::Auth::Basic do |username, password|
  username == 'admin' && password == 'secret'
end
```

Rack은 로깅, 디버깅, URL 라우팅, 인증, 그리고 세센 핸들링을 위한 다양한 표준
미들웨어로 분산되어 있습니다. Sinatra는 설정에 기반하여 이들 컴포넌트들 중
많은 것들을 자동으로 사용하며, 따라서 여러분은 일반적으로는 `use`를 명시적으로
사용할 필요가 없을 것입니다.

[rack](https://github.com/rack/rack/tree/master/lib/rack),
[rack-contrib](https://github.com/rack/rack-contrib#readme),
[Rack wiki](https://github.com/rack/rack/wiki/List-of-Middleware)
에서 유용한 미들웨어들을 찾을 수 있습니다.

## 테스팅(Testing)

Sinatra 테스트는 많은 Rack 기반 테스팅 라이브러리, 프레임워크를 사용하여 작성가능합니다.
그 중 [Rack::Test](http://www.rubydoc.info/github/brynary/rack-test/master/frames)를 권장합니다.

```ruby
require 'my_sinatra_app'
require 'minitest/autorun'
require 'rack/test'

class MyAppTest < Minitest::Test
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def test_my_default
    get '/'
    assert_equal 'Hello World!', last_response.body
  end

  def test_with_params
    get '/meet', :name => 'Frank'
    assert_equal 'Hello Frank!', last_response.body
  end

  def test_with_rack_env
    get '/', {}, 'HTTP_USER_AGENT' => 'Songbird'
    assert_equal "You're using Songbird!", last_response.body
  end
end
```

주의: Sinatra를 모듈러 방식으로 사용한다면, `Sinatra::Application`
를 앱에서 사용하는 클래스 이름으로 바꾸세요.

## Sinatra::Base - 미들웨어(Middleware), 라이브러리(Libraries), 그리고 모듈 앱(Modular Apps)

톱레벨에서 앱을 정의하는 것은 마이크로 앱(micro-app) 수준에서는 잘 동작하지만,
Rack 미들웨어나, Rails 메탈(metal) 또는 서버 컴포넌트를 갖는 간단한 라이브러리,
또는 더 나아가 Sinatra 익스텐션(extension) 같은 재사용 가능한 컴포넌트들을 구축할
경우에는 심각한 약점이 있습니다. 톱레벨은 마이크로 앱 스타일의 설정을 가정하는 것
입니다. (즉, 하나의 단일 애플리케이션 파일과 `./public` 및 `./views` 디렉터리,
로깅, 예외 상세 페이지 등등). 이 곳에서 `Sinatra::Base`가 필요합니다.

```ruby
require 'sinatra/base'

class MyApp < Sinatra::Base
  set :sessions, true
  set :foo, 'bar'

  get '/' do
    'Hello world!'
  end
end
```

`Sinatra::Base` 서브클래스에서 사용가능한 메서드들은 톱레벨 DSL로 접근 가능한 것들과
동일합니다. 대부분의 톱레벨 앱들은 다음 두 가지만 수정하면 `Sinatra::Base` 컴포넌트로
변환 가능합니다.

* 파일은 `sinatra`가 아닌 `sinatra/base`를 require해야 합니다.
  그렇지 않으면 모든 Sinatra의 DSL 메서드들이 메인 네임스페이스에 불러지게
  됩니다.
* 앱의 라우터, 예외 핸들러, 필터, 옵션은 `Sinatra::Base`의 서브클래스에 두어야
  합니다.

`Sinatra::Base`는 백지상태(blank slate)입니다. 빌트인 서버를 비롯한 대부분의 옵션들이
기본값으로 꺼져 있습니다. 가능한 옵션들과 그 작동에 대한 상세는 [옵션과
설정](http://www.sinatrarb.com/configuration.html)을 참조하세요.

### 모듈(Modular) vs. 전통적 방식(Classic Style)

일반적인 믿음과는 반대로, 전통적 방식에 잘못된 부분은 없습니다. 여러분 애플리케이션에
맞다면, 모듈 애플리케이션으로 전환할 필요는 없습니다.

모듈 방식이 아닌 전통적 방식을 사용할 경우 생기는 주된 단점은 루비 프로세스 당
하나의 Sinatra 애플리케이션만 사용할 수 있다는 점입니다. 만약 하나 이상을 사용할
계획이라면 모듈 방식으로 전환하세요. 모듈 방식과 전통적 방식을 섞어쓰지 못할
이유는 없습니다.

방식을 전환할 경우에는, 기본값 설정의 미묘한 차이에 유의해야 합니다.

<table>
  <tr>
    <th>설정</th>
    <th>전통적 방식</th>
    <th>모듈</th>
  </tr>
  <tr>
    <td>app_file</td>
    <td>sinatra를 로딩하는 파일</td>
    <td>Sinatra::Base를 서브클래싱한 파일</td>
  </tr>
  <tr>
    <td>run</td>
    <td>$0 == app_file</td>
    <td>false</td>
  </tr>
  <tr>
    <td>logging</td>
    <td> true</td>
    <td>false</td>
  </tr>
  <tr>
    <td>method_override</td>
    <td>true</td>
    <td>false</td>
  </tr>
  <tr>
    <td>inline_templates</td>
    <td>true</td>
    <td>false</td>
  </tr>
  <tr>
    <td>static</td>
    <td>true</td>
    <td>File.exist?(public_folder)</td>
  </tr>
</table>

### 모듈 애플리케이션(Modular Application) 제공하기

모듈 앱을 시작하는 두 가지 일반적인 옵션이 있습니다.
`run!`으로 능동적으로 시작하는 방법은 이렇습니다.

```ruby
# my_app.rb
require 'sinatra/base'

class MyApp < Sinatra::Base
  # ... 여기에 앱 코드가 온다 ...

  # 루비 파일이 직접 실행될 경우에 서버를 시작
  run! if app_file == $0
end
```

이렇게 시작할 수도 있습니다.

```shell
ruby my_app.rb
```

`config.ru`와 함께 사용할수도 있습니다. 이 경우는 어떠한 Rack 핸들러도 사용할 수 있도록
허용 합다.

```ruby
# config.ru
require './my_app'
run MyApp
```

실행은 이렇게 합니다.

```shell
rackup -p 4567
```

### config.ru로 전통적 방식의 애플리케이션 사용하기

앱 파일을 다음과 같이 작성합니다.

```ruby
# app.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

대응하는 `config.ru`는 다음과 같이 작성합니다.

```ruby
require './app'
run Sinatra::Application
```

### 언제 config.ru를 사용할까?

`config.ru`는 다음 경우에 권장 됩니다.

* 다른 Rack 핸들러(Passenger, Unicorn, Heroku, ...)로 배포하고자 할 때.
* 하나 이상의 `Sinatra::Base` 서브클래스를 사용하고자 할 때.
* Sinatra를 최종점(endpoint)이 아니라, 오로지 미들웨어로만 사용하고자 할 때.

**모듈 방식으로 전환했다는 이유만으로 `config.ru`로 전환할 필요는 없으며,
또한 `config.ru`를 사용한다고 해서 모듈 방식을 사용해야 하는 것도 아닙니다.**

### Sinatra를 미들웨어로 사용하기

Sinatra에서 다른 Rack 미들웨어를 사용할 수 있을 뿐 아니라,
어떤 Sinatra 애플리케이션에서도 순차로 어떠한 Rack 종착점 앞에 미들웨어로
추가될 수 있습니다. 이 종착점은 다른 Sinatra 애플리케이션이 될 수도 있고,
또는 Rack 기반의 어떠한 애플리케이션(Rails/Ramaze/Camping/...)이 될 수도
있습니다.

```ruby
require 'sinatra/base'

class LoginScreen < Sinatra::Base
  enable :sessions

  get('/login') { haml :login }

  post('/login') do
    if params['name'] == 'admin' && params['password'] == 'admin'
      session['user_name'] = params['name']
    else
      redirect '/login'
    end
  end
end

class MyApp < Sinatra::Base
  # 미들웨어는 사전 필터보다 앞서 실행됨
  use LoginScreen

  before do
unless session['user_name']
  halt "접근 거부됨, <a href='/login'>로그인</a> 하세요."
end
  end

  get('/') { "Hello #{session['user_name']}." }
end
```

### 동적인 애플리케이션 생성(Dynamic Application Creation)

어떤 상수에 할당하지 않고 런타임에서 새 애플리케이션들을 생성하려면,
`Sinatra.new`를 쓰면 됩니다.

```ruby
require 'sinatra/base'
my_app = Sinatra.new { get('/') { "hi" } }
my_app.run!
```

선택적 인자로 상속할 애플리케이션을 받을 수 있습니다.

```ruby
# config.ru
require 'sinatra/base'

controller = Sinatra.new do
  enable :logging
  helpers MyHelpers
end

map('/a') do
  run Sinatra.new(controller) { get('/') { 'a' } }
end

map('/b') do
  run Sinatra.new(controller) { get('/') { 'b' } }
end
```

이 방법은 Sintra 익스텐션을 테스팅하거나 또는 여러분의 라이브러리에서 Sinatra를
사용할 경우에 특히 유용합니다.

이 방법은 Sinatra를 미들웨어로 사용하는 것을 아주 쉽게 만들어 주기도 합니다.

```ruby
require 'sinatra/base'

use Sinatra do
  get('/') { ... }
end

run RailsProject::Application
```

## 범위(Scopes)와 바인딩(Binding)

현재 어느 범위에 있느냐가 어떤 메서드와 변수를 사용할 수 있는지를 결정합니다.

### 애플리케이션/클래스 범위

모든 Sinatra 애플리케이션은 `Sinatra::Base`의 서브클래스에 대응됩니다.
만약 톱레벨 DSL (`require 'sinatra'`)을 사용한다면, 이 클래스는
`Sinatra::Application`이며, 그렇지 않을 경우라면 여러분이 명시적으로 생성한
그 서브클래스가 됩니다. 클래스 레벨에서는 `get` 이나 `before` 같은 메서드들을
가지나, `request` 객체나 `session` 에는 접근할 수 없습니다. 왜냐면 모든 요청에
대해 애플리케이션 클래스는 오직 하나이기 때문입니다.

`set`으로 생성한 옵션들은 클래스 레벨의 메서드들입니다.

```ruby
class MyApp < Sinatra::Base
  # 저기요, 저는 애플리케이션 범위에 있다구요!
  set :foo, 42
  foo # => 42

  get '/foo' do
    # 저기요, 전 이제 더 이상 애플리케이션 범위 속에 있지 않아요!
  end
end
```

애플리케이션 범위에는 이런 것들이 있습니다.

* 애플리케이션 클래스 본문
* 확장으로 정의된 메서드
* `helpers`로 전달된 블록
* `set`의 값으로 사용된 Procs/blocks
* `Sinatra.new`로 전달된 블록

범위 객체 (클래스)는 다음과 같이 접근할 수 있습니다.

* configure 블록으로 전달된 객체를 통해(`configure { |c| ... }`)
* 요청 범위 내에서 `settings`

### 요청/인스턴스 범위

매 요청마다, 애플리케이션 클래스의 새 인스턴스가 생성되고 모든 핸들러 블록은
그 범위 내에서 실행됩니다. 범위 내에서 여러분은 `request` 와 `session` 객체에
접근하거나 `erb` 나 `haml` 같은 렌더링 메서드를 호출할 수 있습니다. 요청 범위
내에서 `settings` 헬퍼를 통해 애플리케이션 범위에 접근 가능합니다.

```ruby
class MyApp < Sinatra::Base
  # 이봐요, 전 애플리케이션 범위에 있다구요!
  get '/define_route/:name' do
    # '/define_route/:name'의 요청 범위
    @value = 42

    settings.get("/#{params['name']}") do
      # "/#{params['name']}"의 요청 범위
      @value # => nil (동일한 요청이 아님)
    end

    "라우터가 정의됨!"
  end
end
```

요청 범위에는 이런 것들이 있습니다.

* get/head/post/put/delete/options 블록
* before/after 필터
* 헬퍼(helper) 메서드
* 템플릿/뷰

### 위임 범위(Delegation Scope)

위임 범위(delegation scope)는 메서드를 단순히 클래스 범위로 보냅니다(forward).
하지만 클래스 바인딩을 갖지 않기에 완전히 클래스 범위처럼 동작하지는 않습니다.
오직 명시적으로 위임(delegation) 표시된 메서드들만 사용 가능하고,
또한 클래스 범위와 변수/상태를 공유하지 않습니다 (유의: `self`가 다름).
`Sinatra::Delegator.delegate :method_name`을 호출하여 메서드 위임을 명시적으로
추가할 수 있습니다.

위임 범위에는 이런 것들이 있습니다.

* 톱레벨 바인딩, `require "sinatra"`를 한 경우
* `Sinatra::Delegator` 믹스인으로 확장된 객체

직접 코드를 살펴보길 바랍니다.
[Sinatra::Delegator 믹스인](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/base.rb#L1609-1633)
은 [메인 객체를 확장한 것](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/main.rb#L28-30)입니다.

## 명령행(Command Line)

Sinatra 애플리케이션은 직접 실행할 수 있습니다.

```shell
ruby myapp.rb [-h] [-x] [-e ENVIRONMENT] [-p PORT] [-o HOST] [-s HANDLER]
```

옵션들은 다음과 같습니다.

```
-h # 도움말
-p # 포트 설정 (기본값은 4567)
-o # 호스트 설정 (기본값은 0.0.0.0)
-e # 환경 설정 (기본값은 development)
-s # rack 서버/핸들러 지정 (기본값은 thin)
-x # mutex 잠금 켜기 (기본값은 off)
```

### 다중 스레드(Multi-threading)

_Konstantin의 [StackOverflow의 답변][so-answer]에서 가져왔습니다_

시나트라는 동시성 모델을 전혀 사용하지 않지만, Thin, Puma, WEBrick 같은
기저의 Rack 핸들러(서버)는 사용합니다. 시나트라 자신은 스레드에 안전하므로
랙 핸들러가 동시성 스레드 모델을 사용한다고해도 문제가 되지는 않습니다.
이는 서버를 시작할 때, 서버에 따른 정확한 호출 방법을 사용했을 때의
이야기입니다. 밑의 예제는 다중 스레드 Thin 서버를 시작하는 방법입니다.

```ruby
# app.rb

require 'sinatra/base'

class App < Sinatra::Base
  get '/' do
    "Hello, World"
  end
end

App.run!

```

서버를 시작하는 명령어는 다음과 같습니다.

```shell
thin --threaded start
```


[so-answer]: http://stackoverflow.com/questions/6278817/is-sinatra-multi-threaded/6282999#6282999)

## 요구사항(Requirement)

다음의 루비 버전은 공식적으로 지원됩니다.
<dl>
  <dt> Ruby 1.8.7 </dt>
  <dd>
    1.8.7은 완전하게 지원되지만, 꼭 그래야할 특별한 이유가 없다면,
    1.9.2로 업그레이드하거나 또는 JRuby나 Rubinius로 전환할 것을 권장합니다.
    1.8.7에 대한 지원은 Sinatra 2.0 이전에는 중단되지 않을 것입니다.
    Ruby 1.8.6은 더이상 지원하지 않습니다.
  </dd>

  <dt> Ruby 1.9.2 </dt>
  <dd>
    1.9.2는 완전하게 지원됩니다. 1.9.2p0은, Sinatra를 실행했을 때 세그먼트 오류가
    발생할수 있으므로 쓰지 마세요. 공식 지원은 Sinatra 1.5 이전에는 중단되지 않을
    것입니다.
  </dd>

  <dt> Ruby 1.9.3 </dt>
  <dd>
    1.9.3은 완전하게 지원되고 권장합니다. 이전 버전에서 1.9.3으로 전환할 경우 모든
    세션이 무효화되므로 주의하세요. 1.9.3에 대한 지원은 Sinatra 2.0 이전에는
    중단되지 않을 것입니다.
  </dd>

  <dt>Ruby 2.x</dt>
  <dd>
    2.x은 완전하게 지원되고 권장합니다. 현재 공식 지원 중지 계획은 없습니다.
  </dd>

  <dt>Rubinius</dt>
  <dd>
    Rubinius는 공식적으로 지원됩니다. (Rubinius >= 2.x)
    <tt>gem install puma</tt>를 권장합니다.
  </dd>

  <dt>JRuby</dt>
  <dd>
    JRuby의 마지막 안정판은 공식적으로 지원됩니다. C 확장을 JRuby와 사용하는
    것은 권장되지 않습니다.
    <tt>gem install trinidad</tt>를 권장합니다.
</dd>
</dl>

새로 나오는 루비 버전도 주시하고 있습니다.

다음 루비 구현체들은 공식적으로 지원하지 않지만
여전히 Sinatra를 실행할 수 있는 것으로 알려져 있습니다.

* JRuby와 Rubinius 예전 버전
* Ruby Enterprise Edition
* MacRuby, Maglev, IronRuby
* Ruby 1.9.0 및 1.9.1 (이 버전들은 사용하지 말 것을 권합니다)

공식적으로 지원하지 않는다는 것의 의미는 무언가가 그 플랫폼에서만 잘못 동작하고,
지원되는 플랫폼에서는 정상적으로 동작할 경우, 우리의 문제가 아니라 그 플랫폼의 문제로
간주한다는 뜻입니다.

또한 우리는 CI를 ruby-head (MRI의 이후 릴리즈) 브랜치에 맞춰 실행하지만,
계속해서 변하고 있기 때문에 아무 것도 보장할 수는 없습니다.
앞으로 나올 2.x가 완전히 지원되길 기대합시다.

Sinatra는 선택한 루비 구현체가 지원하는 어떠한 운영체제에서도 작동해야
합니다.

MacRuby를 사용한다면, gem install control_tower 를 실행해 주세요.

현재 Cardinal, SmallRuby, BlueRuby 또는 1.8.7 이전의 루비 버전에서는
Sinatra를 실행할 수 없을 것입니다.

## 최신(The Bleeding Edge)

Sinatra의 가장 최근 코드를 사용하고자 한다면, 애플리케이션을 마스터 브랜치에 맞춰
실행하면 되므로 부담가지지 마세요. 하지만 덜 안정적일 것입니다.

주기적으로 사전배포(prerelease) 젬을 푸시하기 때문에, 최신 기능들을 얻기 위해
다음과 같이 할 수도 있습니다.

```shell
gem install sinatra --pre
```

### Bundler를 사용하여

여러분 애플리케이션을 최신 Sinatra로 실행하고자 한다면,
[Bundler](http://bundler.io)를 사용할 것을 권장합니다.

우선, 아직 설치하지 않았다면 bundler를 설치합니다.

```shell
gem install bundler
```

그런 다음, 프로젝트 디렉터리에서, `Gemfile`을 만듭니다.

```ruby
source 'https://rubygems.org'
gem 'sinatra', :github => "sinatra/sinatra"

# 다른 의존관계들
gem 'haml'                    # 예를 들어, haml을 사용한다면
gem 'activerecord', '~> 3.0'  # 아마도 ActiveRecord 3.x도 필요할 것
```

`Gemfile`안에 애플리케이션의 모든 의존성을 적어야 합니다.
하지만, Sinatra가 직접적인 의존관계에 있는 것들(Rack과 Tilt)은
Bundler가 자동으로 찾아서 추가할 것입니다.

이제 앱을 실행할 수 있습니다.

```shell
bundle exec ruby myapp.rb
```

### 직접 하기(Roll Your Own)

로컬 클론(clone)을 생성한 다음 `$LOAD_PATH`에 `sinatra/lib` 디렉터리를 주고
여러분 앱을 실행합니다.

```shell
cd myapp
git clone git://github.com/sinatra/sinatra.git
ruby -I sinatra/lib myapp.rb
```

이후에 Sinatra 소스를 업데이트하려면 이렇게 하세요.

```shell
cd myapp/sinatra
git pull
```

### 전역으로 설치(Install Globally)

젬을 직접 빌드할 수 있습니다.

```shell
git clone git://github.com/sinatra/sinatra.git
cd sinatra
rake sinatra.gemspec
rake install
```

만약 젬을 루트로 설치한다면, 마지막 단계는 다음과 같이 해야 합니다.

```shell
sudo rake install
```

## 버저닝(Versioning)

Sinatra는 [시맨틱 버저닝Semantic Versioning](http://semver.org/)
[(번역)](http://surpreem.com/archives/380)의 SemVer,
SemVerTag를 준수합니다.

## 더 읽을 거리(Further Reading)

* [프로젝트 웹사이트](http://www.sinatrarb.com/) - 추가 문서들, 뉴스,
  그리고 다른 리소스들에 대한 링크.
* [기여하기](http://www.sinatrarb.com/contributing) - 버그를 찾았나요?
  도움이 필요한가요? 패치를 하셨나요?
* [이슈 트래커](https://github.com/sinatra/sinatra/issues)
* [트위터](https://twitter.com/sinatra)
* [메일링 리스트](http://groups.google.com/group/sinatrarb/topics)
* IRC: [#sinatra](irc://chat.freenode.net/#sinatra) http://freenode.net
* 슬랙의 [Sinatra & Friends](https://sinatrarb.slack.com)입니다.
  [여기](https://sinatra-slack.herokuapp.com/)에서 가입가능합니다.
* [Sinatra Book](https://github.com/sinatra/sinatra-book/) Cookbook 튜토리얼
* [Sinatra Recipes](http://recipes.sinatrarb.com/) 커뮤니티가 만드는 레시피
* http://www.rubydoc.info/에 있는 [최종 릴리스](http://www.rubydoc.info/gems/sinatra)
  또는 [current HEAD](http://www.rubydoc.info/github/sinatra/sinatra)에 대한 API 문서
* [CI server](https://travis-ci.org/sinatra/sinatra)
