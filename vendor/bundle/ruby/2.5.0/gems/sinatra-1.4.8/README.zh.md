# Sinatra

*注：本文档是英文版的翻译，内容更新有可能不及时。如有不一致的地方，请以英文版为准。*

Sinatra 是一门基于
Ruby 的[领域专属语言](https://en.wikipedia.org/wiki/Domain-specific_language)，致力于轻松、快速地创建网络应用：

```ruby
# myapp.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

安装 Sinatra 这个 gem：

```shell
gem install sinatra
```

然后运行 myapp.rb 中的代码：

```shell
ruby myapp.rb
```

在该地址查看： [http://localhost:4567](http://localhost:4567)

推荐运行 `gem install thin` 安装 Thin。这样，Sinatra 会优先选择 Thin 作为服务器。

## 目录

* [Sinatra](#sinatra)
    * [目录](#目录)
    * [路由](#路由)
    * [条件](#条件)
    * [返回值](#返回值)
    * [自定义路由匹配器](#自定义路由匹配器)
    * [静态文件](#静态文件)
    * [视图 / 模板](#视图--模板)
        * [字面量模板](#字面量模板)
        * [可选的模板语言](#可选的模板语言)
            * [Haml 模板](#haml-模板)
            * [Erb 模板](#erb-模板)
            * [Builder 模板](#builder-模板)
            * [Nokogiri 模板](#nokogiri-模板)
            * [Sass 模板](#sass-模板)
            * [SCSS 模板](#scss-模板)
            * [Less 模板](#less-模板)
            * [Liquid 模板](#liquid-模板)
            * [Markdown 模板](#markdown-模板)
            * [Textile 模板](#textile-模板)
            * [RDoc 模板](#rdoc-模板)
            * [AsciiDoc 模板](#asciidoc-模板)
            * [Radius 模板](#radius-模板)
            * [Markaby 模板](#markaby-模板)
            * [RABL 模板](#rabl-模板)
            * [Slim 模板](#slim-模板)
            * [Creole 模板](#creole-模板)
            * [MediaWiki 模板](#mediawiki-模板)
            * [CoffeeScript 模板](#coffeescript-模板)
            * [Stylus 模板](#stylus-模板)
            * [Yajl 模板](#yajl-模板)
            * [WLang 模板](#wlang-模板)
        * [在模板中访问变量](#在模板中访问变量)
        * [带 `yield` 的模板和嵌套布局](#带-yield-的模板和嵌套布局)
        * [内联模板](#内联模板)
        * [具名模板](#具名模板)
        * [关联文件扩展名](#关联文件扩展名)
        * [添加自定义模板引擎](#添加自定义模板引擎)
        * [自定义模板查找逻辑](#自定义模板查找逻辑)
    * [过滤器](#过滤器)
    * [辅助方法](#辅助方法)
        * [使用会话](#使用会话)
        * [中断请求](#中断请求)
        * [传递请求](#传递请求)
        * [触发另一个路由](#触发另一个路由)
        * [设置响应主体、状态码和响应首部](#设置响应主体状态码和响应首部)
        * [响应的流式传输](#响应的流式传输)
        * [日志](#日志)
        * [媒体类型](#媒体类型)
        * [生成 URL](#生成-url)
        * [浏览器重定向](#浏览器重定向)
        * [缓存控制](#缓存控制)
        * [发送文件](#发送文件)
        * [访问请求对象](#访问请求对象)
        * [附件](#附件)
        * [处理日期和时间](#处理日期和时间)
        * [查找模板文件](#查找模板文件)
    * [配置](#配置)
        * [配置攻击防护](#配置攻击防护)
        * [可选的设置](#可选的设置)
    * [环境](#环境)
    * [错误处理](#错误处理)
        * [未找到](#未找到)
        * [错误](#错误)
    * [Rack 中间件](#rack-中间件)
    * [测试](#测试)
    * [Sinatra::Base - 中间件、库和模块化应用](#sinatrabase---中间件库和模块化应用)
        * [模块化风格 vs. 经典风格](#模块化风格-vs-经典风格)
        * [运行一个模块化应用](#运行一个模块化应用)
        * [使用 config.ru 运行经典风格的应用](#使用-configru-运行经典风格的应用)
        * [何时使用 config.ru？](#何时使用-configru)
        * [把 Sinatra 当作中间件使用](#把-sinatra-当作中间件使用)
        * [创建动态应用](#创建动态应用)
    * [作用域和绑定](#作用域和绑定)
        * [应用/类作用域](#应用类作用域)
        * [请求/实例作用域](#请求实例作用域)
        * [代理作用域](#代理作用域)
    * [命令行](#命令行)
        * [多线程](#多线程)
    * [必要条件](#必要条件)
    * [紧跟前沿](#紧跟前沿)
        * [通过 Bundler 使用 Sinatra](#通过-bundler-使用-sinatra)
        * [使用自己本地的 Sinatra](#使用自己本地的-sinatra)
        * [全局安装](#全局安装)
    * [版本](#版本)
    * [更多资料](#更多资料)

## 路由

在 Sinatra 中，一个路由分为两部分：HTTP 方法和 URL 匹配范式。每个路由都有一个要执行的代码块：

```ruby
get '/' do
  .. 显示内容 ..
end

post '/' do
  .. 创建内容 ..
end

put '/' do
  .. 替换内容 ..
end

patch '/' do
  .. 修改内容 ..
end

delete '/' do
  .. 删除内容 ..
end

options '/' do
  .. 显示命令列表 ..
end

link '/' do
  .. 建立某种联系 ..
end

unlink '/' do
  .. 解除某种联系 ..
end
```

路由按照它们定义时的顺序进行匹配。第一个与请求匹配的路由会被调用。

路由范式可以包括具名参数，具名参数可以通过 `params` hash 访问：

```ruby
get '/hello/:name' do
  # 匹配 "GET /hello/foo" 和 "GET /hello/bar"
  # params['name'] 的值是 'foo' 或者 'bar'
  "Hello #{params['name']}!"
end
```

也可以通过代码块参数访问具名参数：

```ruby
get '/hello/:name' do |n|
  # 匹配 "GET /hello/foo" 和 "GET /hello/bar"
  # params['name'] 的值是 'foo' 或者 'bar'
  # n 存储 params['name'] 的值
  "Hello #{n}!"
end
```

路由范式也可以包含通配符参数， 参数值可以通过 `params['splat']` 数组访问。

```ruby
get '/say/*/to/*' do
  # 匹配 "GET /say/hello/to/world"
  params['splat'] # => ["hello", "world"]
end

get '/download/*.*' do
  # 匹配 "GET /download/path/to/file.xml"
  params['splat'] # => ["path/to/file", "xml"]
end
```

或者通过代码块参数访问：

```ruby
get '/download/*.*' do |path, ext|
  [path, ext] # => ["path/to/file", "xml"]
end
```

通过正则表达式匹配路由：

```ruby
get /\A\/hello\/([\w]+)\z/ do
  "Hello, #{params['captures'].first}!"
end
```

或者使用代码块参数：

```ruby
get %r{/hello/([\w]+)} do |c|
  # 匹配 "GET /meta/hello/world"、"GET /hello/world/1234" 等
  "Hello, #{c}!"
end
```

路由范式可以包含可选参数：

```ruby  
get '/posts/:format?' do
  # 匹配 "GET /posts/" 和任意扩展 "GET /posts/json"、"GET /posts/xml" 等
end
```

路由也可以使用查询参数：

```ruby
get '/posts' do
  # 匹配 "GET /posts?title=foo&author=bar"
  title = params['title']
  author = params['author']
  # 使用 title 和 author 变量；对于 /posts 路由来说，查询字符串是可选的
end
```
顺便一提，除非你禁用了路径遍历攻击防护（见下文），请求路径可能在匹配路由前发生改变。

### 条件

路由可以包含各种匹配条件，比如 user agent：

```ruby
get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
  "你正在使用 Songbird，版本是 #{params['agent'][0]}"
end

get '/foo' do
  # 匹配非 Songbird 浏览器
end
```

其它可以使用的条件有 `host_name` 和 `provides`：

```ruby
get '/', :host_name => /^admin\./ do
  "管理员区域，无权进入！"
end

get '/', :provides => 'html' do
  haml :index
end

get '/', :provides => ['rss', 'atom', 'xml'] do
  builder :feed
end
```

`provides` 会搜索请求的 Accept 首部字段。

也可以轻易地使用自定义条件：

```ruby
set(:probability) { |value| condition { rand <= value } }

get '/win_a_car', :probability => 0.1 do
  "You won!"
end

get '/win_a_car' do
  "Sorry, you lost."
end
```

对于一个需要提供多个值的条件，可以使用 splat：

```ruby
set(:auth) do |*roles|   # <- 注意此处使用了 splat
  condition do
    unless logged_in? && roles.any? {|role| current_user.in_role? role }
      redirect "/login/", 303
    end
  end
end

get "/my/account/", :auth => [:user, :admin] do
  "Your Account Details"
end

get "/only/admin/", :auth => :admin do
  "Only admins are allowed here!"
end
```

### 返回值

路由代码块的返回值至少决定了返回给
HTTP 客户端的响应主体，或者至少决定了在
Rack 堆栈中的下一个中间件。大多数情况下，返回值是一个字符串，就像上面的例子中的一样。但是，其它类型的值也是可以接受的。

你可以返回任何对象，该对象要么是一个合理的 Rack 响应，要么是一个 Rack body 对象，要么是 HTTP 状态码：

* 一个包含三个元素的数组: `[状态 (Fixnum), 响应首部 (Hash), 响应主体 (可以响应 #each 方法)]`
* 一个包含两个元素的数组: `[状态 (Fixnum), 响应主体 (可以响应 #each 方法)]`
* 一个响应 `#each` 方法，只传回字符串的对象
* 一个代表状态码的数字

例如，我们可以轻松地实现流式传输：

```ruby
class Stream
  def each
    100.times { |i| yield "#{i}\n" }
  end
end

get('/') { Stream.new }
```

也可以使用 `stream` 辅助方法（见下文描述）以减少样板代码并在路由中直接使用流式传输。

### 自定义路由匹配器

如上文所示，Sinatra
本身支持使用字符串和正则表达式作为路由匹配。但不限于此，你可以轻松地定义自己的匹配器：

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

上面的例子可能太繁琐了， 因为它也可以用更简单的方式表述：

```ruby
get // do
  pass if request.path_info == "/index"
  # ...
end
```

或者，使用消极向前查找:

```ruby
get %r{^(?!/index$)} do
  # ...
end
```

## 静态文件

静态文件从 `./public` 目录提供服务。可以通过设置`:public_folder` 选项设定一个不同的位置：

```ruby
set :public_folder, File.dirname(__FILE__) + '/static'
```

请注意 public 目录名并没有包含在 URL 中。文件 `./public/css/style.css` 可以通过
`http://example.com/css/style.css` 访问。

可以使用 `:static_cache_control` 设置（见下文）添加 `Cache-Control` 首部信息。

## 视图 / 模板

每一门模板语言都将自身的渲染方法暴露给
Sinatra 调用。这些渲染方法只是简单地返回字符串。

```ruby
get '/' do
  erb :index
end
```

这段代码会渲染 `views/index.erb` 文件。

除了模板文件名，也可以直接传入模板内容：

```ruby
get '/' do
  code = "<%= Time.now %>"
  erb code
end
```

渲染方法接受第二个参数，即选项 hash：

```ruby
get '/' do
  erb :index, :layout => :post
end
```

这段代码会将 `views/index.erb` 嵌入在 `views/post.erb`
布局中并一起渲染（`views/layout.erb` 是默认的布局，如果它存在的话）。

任何 Sinatra 不能理解的选项都会传递给模板引擎。

```ruby
get '/' do
  haml :index, :format => :html5
end
```

也可以为每种模板语言设置通用的选项：

```ruby
set :haml, :format => :html5

get '/' do
  haml :index
end
```

在渲染方法中传入的选项会覆盖通过 `set` 设置的通用选项。

可用的选项：

<dl>
  <dt>locals</dt>
  <dd>
    传递给模板文档的 locals 对象列表。对于 partials
    很方便。例如：<tt>erb "<%= foo %>", :locals => {:foo => "bar"}</tt>
  </dd>

  <dt>default_encoding</dt>
  <dd>默认的字符编码。默认值为 <tt>settings.default_encoding</tt>。</dd>

  <dt>views</dt>
  <dd>存放模板文件的目录。默认为 <tt>settings.views</tt>。</dd>

  <dt>layout</dt>
  <dd>
    是否使用布局 (<tt>true</tt> 或 <tt>false</tt>)。
    如果使用一个符号类型的值，则是用于明确使用的模板。例如：
    <tt>erb :index, :layout => !request.xhr?</tt>
  </dd>

  <dt>content_type</dt>
  <dd>由模板生成的 Content-Type。默认值由模板语言决定。</dd>

  <dt>scope</dt>
  <dd>
    渲染模板时的作用域。默认值为应用类的实例对象。如果更改此项，实例变量和辅助方法将不可用。
  </dd>

  <dt>layout_engine</dt>
  <dd>
    渲染布局所使用的模板引擎。用于不支持布局的模板语言。默认值为模板所使用的引擎。例如：
    <tt>set :rdoc, :layout_engine => :erb</tt>
  </dd>

  <dt>layout_options</dt>
  <dd>
    渲染布局的特殊选项。例如：
    <tt>set :rdoc, :layout_options => { :views => 'views/layouts' }</tt>
  </dd>
</dl>

Sinatra 假定模板文件直接位于 `./views` 目录。要使用不同的视图目录：

```ruby
set :views, settings.root + '/templates'
```


需要牢记的一点是，你必须通过符号引用模板， 即使它们存放在子目录下
（在这种情况下，使用 `:'subdir/template'` 或 `'subdir/template'.to_sym`）。
如果你不使用符号，渲染方法会直接渲染你传入的任何字符串。

### 字面量模板

```ruby
get '/' do
  haml '%div.title Hello World'
end
```

这段代码直接渲染模板字符串。

### 可选的模板语言

一些语言有多种实现。为了确定使用哪种实现（以及保证线程安全），你应该首先引入该实现：

```ruby
require 'rdiscount' # 或 require 'bluecloth'
get('/') { markdown :index }
```

#### Haml 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://haml.info/" title="haml">haml</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.haml</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>haml :index, :format => :html5</tt></td>
  </tr>
</table>

#### Erb 模板

<table>
  <tr>
    <td>依赖项</td>
    <td>
      <a href="http://www.kuwata-lab.com/erubis/" title="erubis">erubis</a>
      或 erb (Ruby 标准库中已经包含)
    </td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.erb</tt>, <tt>.rhtml</tt> or <tt>.erubis</tt> (仅用于 Erubis)</td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>erb :index</tt></td>
  </tr>
</table>

#### Builder 模板

<table>
  <tr>
    <td>依赖项</td>
    <td>
      <a href="https://github.com/jimweirich/builder" title="builder">builder</a>
    </td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.builder</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>builder { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

`builder` 渲染方法也接受一个代码块，用于内联模板（见例子）。

#### Nokogiri 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://www.nokogiri.org/" title="nokogiri">nokogiri</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.nokogiri</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>nokogiri { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

`nokogiri` 渲染方法也接受一个代码块，用于内联模板（见例子）。

#### Sass 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.sass</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>sass :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

#### SCSS 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.scss</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>scss :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

#### Less 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://lesscss.org/" title="less">less</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.less</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>less :stylesheet</tt></td>
  </tr>
</table>

#### Liquid 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://liquidmarkup.org/" title="liquid">liquid</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.liquid</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>liquid :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

因为不能在 Liquid 模板中调用 Ruby 方法（除了 `yield`），你几乎总是需要传递 locals 对象给它。

#### Markdown 模板

<table>
  <tr>
    <td>依赖项</td>
    <td>
      下列任一:
        <a href="https://github.com/davidfstr/rdiscount" title="RDiscount">RDiscount</a>,
        <a href="https://github.com/vmg/redcarpet" title="RedCarpet">RedCarpet</a>,
        <a href="http://deveiate.org/projects/BlueCloth" title="BlueCloth">BlueCloth</a>,
        <a href="http://kramdown.gettalong.org/" title="kramdown">kramdown</a>,
        <a href="https://github.com/bhollis/maruku" title="maruku">maruku</a>
    </td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.markdown</tt>, <tt>.mkd</tt> and <tt>.md</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>markdown :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

不能在 markdown 中调用 Ruby 方法，也不能传递 locals 给它。
因此，你一般会结合其它的渲染引擎来使用它：

```ruby
erb :overview, :locals => { :text => markdown(:introduction) }
```

请注意你也可以在其它模板中调用 markdown 方法：

```ruby
%h1 Hello From Haml!
%p= markdown(:greetings)
```

因为不能在 Markdown 中使用 Ruby 语言，你不能使用 Markdown 书写的布局。
不过，使用其它渲染引擎作为模板的布局是可能的，这需要通过传入 `:layout_engine` 选项。

#### Textile 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://redcloth.org/" title="RedCloth">RedCloth</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.textile</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>textile :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

不能在 textile 中调用 Ruby 方法，也不能传递 locals 给它。
因此，你一般会结合其它的渲染引擎来使用它：

```ruby
erb :overview, :locals => { :text => textile(:introduction) }
```

请注意你也可以在其他模板中调用 `textile` 方法：

```ruby
%h1 Hello From Haml!
%p= textile(:greetings)
```

因为不能在 Textile 中调用 Ruby 方法，你不能用 Textile 书写布局。
不过，使用其它渲染引擎作为模版的布局是可能的，这需要通过传递 `:layout_engine` 选项。

#### RDoc 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://rdoc.sourceforge.net/" title="RDoc">RDoc</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.rdoc</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>rdoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

不能在 rdoc 中调用 Ruby 方法，也不能传递 locals 给它。
因此，你一般会结合其它的渲染引擎来使用它：

```ruby
erb :overview, :locals => { :text => rdoc(:introduction) }
```

请注意你也可以在其他模板中调用 `rdoc` 方法：

```ruby
%h1 Hello From Haml!
%p= rdoc(:greetings)
```

因为不能在 RDoc 中调用 Ruby 方法，你不能用 RDoc 书写布局。
不过，使用其它渲染引擎作为模版的布局是可能的，这需要通过传递 `:layout_engine` 选项。

#### AsciiDoc 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://asciidoctor.org/" title="Asciidoctor">Asciidoctor</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.asciidoc</tt>, <tt>.adoc</tt> and <tt>.ad</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>asciidoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

因为不能在 AsciiDoc 模板中直接调用 Ruby 方法，你几乎总是需要传递 locals 对象给它。

#### Radius 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="https://github.com/jlong/radius" title="Radius">Radius</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.radius</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>radius :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

因为不能在 Radius 模板中直接调用 Ruby 方法，你几乎总是可以传递 locals 对象给它。

#### Markaby 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://markaby.github.io/" title="Markaby">Markaby</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.mab</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>markaby { h1 "Welcome!" }</tt></td>
  </tr>
</table>

`markaby` 渲染方法也接受一个代码块，用于内联模板（见例子）。

#### RABL 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="https://github.com/nesquena/rabl" title="Rabl">Rabl</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.rabl</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>rabl :index</tt></td>
  </tr>
</table>

#### Slim 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="http://slim-lang.com/" title="Slim Lang">Slim Lang</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.slim</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>slim :index</tt></td>
  </tr>
</table>

#### Creole 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="https://github.com/minad/creole" title="Creole">Creole</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.creole</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>creole :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

不能在 creole 中调用 Ruby 方法，也不能传递 locals 对象给它。
因此你一般会结合其它的渲染引擎来使用它：

```ruby
erb :overview, :locals => { :text => creole(:introduction) }
```

注意你也可以在其它模板内调用 `creole` 方法：

```ruby
%h1 Hello From Haml!
%p= creole(:greetings)
```

因为不能在 Creole 模板文件内调用 Ruby 方法，你不能用 Creole 书写布局文件。
然而，使用其它渲染引擎作为模版的布局是可能的，这需要通过传递 `:layout_engine` 选项。

#### MediaWiki 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="https://github.com/nricciar/wikicloth" title="WikiCloth">WikiCloth</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.mediawiki</tt> and <tt>.mw</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>mediawiki :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

在 MediaWiki 标记文件内不能调用 Ruby 方法，也不能传递 locals 对象给它。
因此你一般会结合其它的渲染引擎来使用它：

```ruby
erb :overview, :locals => { :text => mediawiki(:introduction) }
```

注意你也可以在其它模板内调用 `mediawiki` 方法：

```ruby
%h1 Hello From Haml!
%p= mediawiki(:greetings)
```

因为不能在 MediaWiki 文件内调用 Ruby 方法，你不能用 MediaWiki 书写布局文件。
然而，使用其它渲染引擎作为模版的布局是可能的，这需要通过传递 `:layout_engine` 选项。

#### CoffeeScript 模板

<table>
  <tr>
    <td>依赖项</td>
    <td>
      <a href="https://github.com/josh/ruby-coffee-script" title="Ruby CoffeeScript">
        CoffeeScript
      </a> 以及一种
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        执行 JavaScript 的方式
      </a>
    </td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.coffee</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>coffee :index</tt></td>
  </tr>
</table>

#### Stylus 模板

<table>
  <tr>
    <td>依赖项</td>
    <td>
      <a href="https://github.com/forgecrafted/ruby-stylus" title="Ruby Stylus">
        Stylus
      </a> 以及一种
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        执行 JavaScript 的方式
      </a>
    </td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.styl</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>stylus :index</tt></td>
  </tr>
</table>

在使用 Stylus 模板之前，你需要先加载 `stylus` 和 `stylus/tilt`：

```ruby
require 'sinatra'
require 'stylus'
require 'stylus/tilt'

get '/' do
  stylus :example
end
```

#### Yajl 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="https://github.com/brianmario/yajl-ruby" title="yajl-ruby">yajl-ruby</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.yajl</tt></td>
  </tr>
  <tr>
    <td>例子</td>
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

模板文件的源码作为一个 Ruby 字符串被求值，得到的 json 变量是通过 `#to_json` 方法转换的：

```ruby
json = { :foo => 'bar' }
json[:baz] = key
```

可以使用 `:callback` 和 `:variable` 选项装饰被渲染的对象：

```javascript
var resource = {"foo":"bar","baz":"qux"};
present(resource);
```

#### WLang 模板

<table>
  <tr>
    <td>依赖项</td>
    <td><a href="https://github.com/blambeau/wlang/" title="WLang">WLang</a></td>
  </tr>
  <tr>
    <td>文件扩展名</td>
    <td><tt>.wlang</tt></td>
  </tr>
  <tr>
    <td>例子</td>
    <td><tt>wlang :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

因为在 WLang 中调用 Ruby 方法不符合语言习惯，你几乎总是需要传递 locals 给 WLang 木板。
然而，可以用 WLang 编写布局文件，也可以在 WLang 中使用 `yield` 方法。

### 在模板中访问变量

模板的求值发生在路由处理器内部的上下文中。模板可以直接访问路由处理器中设置的实例变量。

```ruby
get '/:id' do
  @foo = Foo.find(params['id'])
  haml '%h1= @foo.name'
end
```

或者，也可以显式地指定一个由局部变量组成的 locals 哈希：

```ruby
get '/:id' do
  foo = Foo.find(params['id'])
  haml '%h1= foo.name', :locals => { :foo => foo }
end
```

locals 哈希典型的使用情景是在别的模板中渲染 partials。

### 带 `yield` 的模板和嵌套布局

布局通常就是使用了 `yield` 方法的模板。
这样的布局文件可以通过上面描述的 `:template` 选项指定，也可以通过下面的代码块渲染：

```ruby
erb :post, :layout => false do
  erb :index
end
```

这段代码几乎完全等同于 `erb :index, :layout => :post`。

向渲染方法传递代码块对于创建嵌套布局是最有用的：

```ruby
erb :main_layout, :layout => false do
  erb :admin_layout do
    erb :user
  end
end
```

代码行数可以更少：

```ruby
erb :admin_layout, :layout => :main_layout do
  erb :user
end
```

当前，以下的渲染方法接受一个代码块：`erb`、`haml`、`liquid`、`slim ` 和 `wlang`。
通用的 `render` 方法也接受。

### 内联模板

模板可以在源文件的末尾定义：

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

注意：在引入了 sinatra 的源文件中定义的内联模板会自动载入。
如果你在其他源文件中也有内联模板，需要显式调用 `enable :inline_templates`。

### 具名模板

可以使用顶层 `template` 方法定义模板：

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

如果存在名为 “layout” 的模板，该模板会在每个模板渲染的时候作为布局使用。
你可以为渲染方法传送 `:layout => false` 来禁用该次渲染的布局，
也可以设置 `set :haml, :layout => false` 来默认禁用布局。

```ruby
get '/' do
  haml :index, :layout => !request.xhr?
end
```

### 关联文件扩展名

为了将一个文件扩展名到对应的模版引擎，要使用 `Tilt.register`。
比如，如果你喜欢使用 `tt` 作为 Textile 模版的扩展名，你可以这样做:

```ruby
Tilt.register :tt, Tilt[:textile]
```

### 添加自定义模板引擎

首先，通过 Tilt 注册你自定义的引擎，然后创建一个渲染方法：

```ruby
Tilt.register :myat, MyAwesomeTemplateEngine

helpers do
  def myat(*args) render(:myat, *args) end
end

get '/' do
  myat :index
end
```

这段代码将会渲染 `./views/index.myat` 文件。
查看 https://github.com/rtomayko/tilt 以了解更多关于 Tilt 的信息。

### 自定义模板查找逻辑

要实现自定义的模板查找机制，你可以构建自己的 `#find_template` 方法：

```ruby
configure do
  set :views, [ './views/a', './views/b' ]
end

def find_template(views, name, engine, &block)
  Array(views).each do |v|
    super(v, name, engine, &block)
  end
end
```

## 过滤器

`before` 过滤器在每个请求之前调用，调用的上下文与请求的上下文相同，并且可以修改请求和响应。
在过滤器中设置的变量可以被路由和模板访问：

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

`after` 过滤器在每个请求之后调用，调用上下文与请求的上下文相同，并且也会修改请求和响应。
在 `before` 过滤器和路由中设置的实例变量可以被 `after` 过滤器访问：

```ruby
after do
  puts response.status
end
```

请注意：除非你显式使用 `body` 方法，而不是在路由中直接返回字符串，
响应主体在 `after` 过滤器是不可访问的， 因为它在之后才会生成。

过滤器可以可选地带有范式， 只有请求路径满足该范式时才会执行：

```ruby
before '/protected/*' do
  authenticate!
end

after '/create/:slug' do |slug|
  session['last_slug'] = slug
end
```

和路由一样，过滤器也可以带有条件：

```ruby
before :agent => /Songbird/ do
  # ...
end

after '/blog/*', :host_name => 'example.com' do
  # ...
end
```

## 辅助方法

使用顶层的 `helpers` 方法来定义辅助方法， 以便在路由处理器和模板中使用：

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

也可以在多个分散的模块中定义辅助方法：

```ruby
module FooUtils
  def foo(name) "#{name}foo" end
end

module BarUtils
  def bar(name) "#{name}bar" end
end

helpers FooUtils, BarUtils
```

以上代码块与在应用类中包含模块等效。

### 使用会话

会话用于在请求之间保持状态。如果激活了会话，每一个用户会话都对应一个会话 hash：

```ruby
enable :sessions

get '/' do
  "value = " << session['value'].inspect
end

get '/:value' do
  session['value'] = params['value']
end
```

请注意 `enable :sessions` 实际将所有的数据保存在一个 cookie 中。
这可能并不总是你想要的（cookie 中存储大量的数据会增加你的流量）。
你可以使用任何 Rack session 中间件：要达到此目的，**不要**使用 `enable :sessions`，
而是按照自己的需要引入想使用的中间件：

```ruby
use Rack::Session::Pool, :expire_after => 2592000

get '/' do
  "value = " << session['value'].inspect
end

get '/:value' do
  session['value'] = params['value']
end
```

为提高安全性，cookie 中的会话数据会被一个会话密码保护。Sinatra 会为你生成一个随机的密码。
然而，每次启动应用时，该密码都会变化，你也可以自己设置该密码，以便所有的应用实例共享：

```
set :session_secret, 'super secret'
```

如果你想进一步配置会话，可以在设置 `sessions` 时提供一个选项 hash 作为第二个参数：

```
set :sessions, :domain => 'foo.com'
```

为了在 foo.com 的子域名间共享会话数据，可以在域名前添加一个 *.*：

```ruby
set :sessions, :domain => '.foo.com'
```

### 中断请求

要想在过滤器或路由中立即中断一个请求：

```ruby
halt
```

你也可以指定中断时的状态码：

```ruby
halt 410
```

或者响应主体：

```ruby
halt 'this will be the body'
```

或者同时指定两者：

```ruby
halt 401, 'go away!'
```

也可以指定响应首部：

```ruby
halt 402, {'Content-Type' => 'text/plain'}, 'revenge'
```

当然也可以使用模板：

```
halt erb(:error)
```

### 传递请求

一个路由可以放弃对请求的处理并将处理让给下一个匹配的路由，这要通过 `pass` 实现：

```ruby
get '/guess/:who' do
  pass unless params['who'] == 'Frank'
  'You got me!'
end

get '/guess/*' do
  'You missed!'
end
```

执行 `pass` 后，控制流从该路由代码块直接退出，并继续前进到下一个匹配的路由。
如果没有匹配的路由，将返回 404。

### 触发另一个路由

有些时候，`pass` 并不是你想要的，你希望得到的是调用另一个路由的结果。
使用 `call` 就可以做到这一点:

```ruby
get '/foo' do
  status, headers, body = call env.merge("PATH_INFO" => '/bar')
  [status, headers, body.map(&:upcase)]
end

get '/bar' do
  "bar"
end
```

请注意在以上例子中，你只需简单地移动 `"bar"` 到一个被 `/foo` 和 `/bar` 同时使用的辅助方法中，
就可以简化测试和增加性能。

如果你希望请求发送到同一个应用，而不是应用副本，应使用 `call!` 而不是 `call`。

如果想更多了解关于 `call` 的信息，请查看 Rack 规范。

### 设置响应主体、状态码和响应首部

推荐在路由代码块的返回值中设定状态码和响应主体。
但是，在某些场景下你可能想在别处设置响应主体，这时你可以使用 `body` 辅助方法。
设置之后，你可以在那以后使用该方法访问响应主体：

```ruby
get '/foo' do
  body "bar"
end

after do
  puts body
end
```

也可以传递一个代码块给 `body` 方法，
它会被 Rack 处理器执行（这可以用来实现流式传输，参见“返回值”）。

与响应主体类似，你也可以设定状态码和响应首部：

```ruby
get '/foo' do
  status 418
  headers \
    "Allow"   => "BREW, POST, GET, PROPFIND, WHEN",
    "Refresh" => "Refresh: 20; http://www.ietf.org/rfc/rfc2324.txt"
  body "I'm a tea pot!"
end
```

正如 `body` 方法，不带参数调用 `headers` 和 `status` 方法可以访问它们的当前值。

### 响应的流式传输

有时你可能想在完全生成响应主体前返回数据。
更极端的情况是，你希望在客户端关闭连接前一直发送数据。
为满足这些需求，可以使用 `stream` 辅助方法而不必重新造轮子：

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

`stream` 辅助方法允许你实现流式 API 和
[服务器端发送事件](https://w3c.github.io/eventsource/)，
同时它也是实现 [WebSockets](https://en.wikipedia.org/wiki/WebSocket) 的基础。
如果你应用的部分（不是全部）内容依赖于访问缓慢的资源，它也可以用来提高并发能力。

请注意流式传输，尤其是并发请求数，高度依赖于应用所使用的服务器。
一些服务器可能根本不支持流式传输。
如果服务器不支持，传递给 `stream` 方法的代码块执行完毕之后，响应主体会一次性地发送给客户端。
Shotgun 完全不支持流式传输。

如果 `:keep_open` 作为可选参数传递给 `stream` 方法，将不会在流对象上调用 `close` 方法，
这允许你在控制流的下游某处手动关闭。该参数只对事件驱动的服务器（如 Thin 和 Rainbows）生效。
其它服务器仍会关闭流式传输：

```ruby
# 长轮询

set :server, :thin
connections = []

get '/subscribe' do
  # 在服务器端的事件中注册客户端
  stream(:keep_open) do |out|
    connections << out
    # 清除关闭的连接
    connections.reject!(&:closed?)
  end
end

post '/:message' do
  connections.each do |out|
    # 通知客户端有条新消息
    out << params['message'] << "\n"

    # 使客户端重新连接
    out.close
  end

  # 确认
  "message received"
end
```

### 日志

在请求作用域下，`logger` 辅助方法会返回一个 `Logger` 类的实例：

```ruby
get '/' do
  logger.info "loading data"
  # ...
end
```

该 `logger` 方法会自动参考 Rack 处理器的日志设置。
若日志被禁用，该方法会返回一个无关痛痒的对象，所以你完全不必担心这会影响路由和过滤器。

注意只有 `Sinatra::Application` 默认开启了日志，若你的应用继承自 `Sinatra::Base`，
很可能需要手动开启：

```ruby
class MyApp < Sinatra::Base
  configure :production, :development do
    enable :logging
  end
end
```

为避免使用任何与日志有关的中间件，需要将 `logging` 设置项设为 `nil`。
然而，在这种情况下，`logger` 辅助方法会返回 `nil`。
一种常见的使用场景是你想要使用自己的日志工具。
Sinatra 会使用 `env['rack.logger']` 的值作为日志工具，无论该值是什么。

### 媒体类型

使用 `send_file` 或者静态文件的时候，Sinatra 可能不会识别你的媒体类型。
使用 `mime_type` 通过文件扩展名来注册媒体类型：

```ruby
mime_type :foo, 'text/foo'
```

你也可以使用 `content_type` 辅助方法：

```ruby
get '/' do
  content_type :foo
  "foo foo foo"
end
```

### 生成 URL

为了生成 URL，你应当使用 `url` 辅助方法，例如，在 Haml 中：

```ruby
%a{:href => url('/foo')} foo
```

如果使用了反向代理和 Rack 路由，生成 URL 的时候会考虑这些因素。

这个方法还有一个别名 `to` (见下面的例子)。

### 浏览器重定向

你可以通过 `redirect` 辅助方法触发浏览器重定向：

```ruby
get '/foo' do
  redirect to('/bar')
end
```

其他参数的用法，与 `halt` 相同：

```ruby
redirect to('/bar'), 303
redirect 'http://www.google.com/', 'wrong place, buddy'
```

用 `redirect back` 可以把用户重定向到原始页面：

```ruby
get '/foo' do
  "<a href='/bar'>do something</a>"
end

get '/bar' do
  do_something
  redirect back
end
```

如果想传递参数给 redirect，可以用查询字符串：

```ruby
redirect to('/bar?sum=42')
```

或者使用会话：

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

### 缓存控制

正确设置响应首部是合理利用 HTTP 缓存的基础。

可以这样设定 Cache-Control 首部字段：

```ruby
get '/' do
  cache_control :public
  "cache it!"
end
```

核心提示: 应当在 `before` 过滤器中设定缓存。

```ruby
before do
  cache_control :public, :must_revalidate, :max_age => 60
end
```

如果你使用 `expires` 辅助方法设定响应的响应首部， 会自动设定 `Cache-Control` 字段：

```ruby
before do
  expires 500, :public, :must_revalidate
end
```

为了合理使用缓存，你应该考虑使用 `etag` 或 `last_modified` 方法。
推荐在执行繁重任务*之前*使用这些辅助方法，这样一来，
如果客户端在缓存中已经有相关内容，就会立即得到响应：

```ruby
get '/article/:id' do
  @article = Article.find params['id']
  last_modified @article.updated_at
  etag @article.sha1
  erb :article
end
```

也可以使用 [weak ETag](https://en.wikipedia.org/wiki/HTTP_ETag#Strong_and_weak_validation)：

```ruby
etag @article.sha1, :weak
```

这些辅助方法并不会为你做任何缓存，而是将必要的信息发送给你的缓存。
如果你正在寻找快捷的反向代理缓存方案，可以尝试
[rack-cache](https://github.com/rtomayko/rack-cache)：

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

使用 `:statis_cache_control` 设置（见下文）为静态文件添加 `Cache-Control` 首部字段。

根据 RFC 2616，如果 If-Match 或 If-None-Match 首部设置为 `*`，根据所请求的资源存在与否，
你的应用应当有不同的行为。
Sinatra 假设安全请求（如 GET）和幂等性请求（如 PUT）所访问的资源是已经存在的，
而其它请求（如 POST 请求）所访问的资源是新资源。
你可以通过传入 `:new_resource` 选项改变这一行为。

```ruby
get '/create' do
  etag '', :new_resource => true
  Article.create
  erb :new_article
end
```

如果你仍想使用 weak ETag，可以传入一个 `:kind` 选项：

```ruby
etag '', :new_resource => true, :kind => :weak
```

### 发送文件

为了将文件的内容作为响应返回，可以使用 `send_file` 辅助方法：

```ruby
get '/' do
  send_file 'foo.png'
end
```

该辅助方法接受一些选项:

```ruby
send_file 'foo.png', :type => :jpg
```

可用的选项有:

<dl>
  <dt>filename</dt>
  <dd>响应中使用的文件名，默认是真实的文件名。</dd>

  <dt>last_modified</dt>
  <dd>Last-Modified 响应首部的值，默认是文件的 mtime （修改时间）。</dd>

  <dt>type</dt>
  <dd>Content-Type 响应首部的值，如果未指定，会根据文件扩展名猜测。</dd>

  <dt>disposition</dt>
  <dd>
    Content-Disposition 响应首部的值，
    可选的值有： <tt>nil</tt> (默认)、<tt>:attachment</tt> 和
    <tt>:inline</tt>
  </dd>

  <dt>length</dt>
  <dd>Content-Length 响应首部的值，默认是文件的大小。</dd>

  <dt>status</dt>
  <dd>
    将要返回的状态码。当以一个静态文件作为错误页面时，这很有用。

    如果 Rack 处理器支持的话，Ruby 进程也能使用除 streaming 以外的方法。
    如果你使用这个辅助方法， Sinatra会自动处理 range 请求。
  </dd>
</dl>

### 访问请求对象

传入的请求对象可以在请求层（过滤器、路由、错误处理器内部）通过 `request` 方法访问：

```ruby
# 在 http://example.com/example 上运行的应用
get '/foo' do
  t = %w[text/css text/html application/javascript]
  request.accept              # ['text/html', '*/*']
  request.accept? 'text/xml'  # true
  request.preferred_type(t)   # 'text/html'
  request.body                # 客户端设定的请求主体（见下文）
  request.scheme              # "http"
  request.script_name         # "/example"
  request.path_info           # "/foo"
  request.port                # 80
  request.request_method      # "GET"
  request.query_string        # ""
  request.content_length      # request.body 的长度
  request.media_type          # request.body 的媒体类型
  request.host                # "example.com"
  request.get?                # true (其它动词也具有类似方法)
  request.form_data?          # false
  request["some_param"]       # some_param 参数的值。[] 是访问 params hash 的捷径
  request.referrer            # 客户端的 referrer 或者 '/'
  request.user_agent          # 用户代理 (:agent 条件使用该值)
  request.cookies             # 浏览器 cookies 哈希
  request.xhr?                # 这是否是 ajax 请求？
  request.url                 # "http://example.com/example/foo"
  request.path                # "/example/foo"
  request.ip                  # 客户端 IP 地址
  request.secure?             # false （如果是 ssl 则为 true）
  request.forwarded?          # true （如果是运行在反向代理之后）
  request.env                 # Rack 中使用的未处理的 env hash
end
```

一些选项，例如 `script_name` 或者 `path_info` 也是可写的：

```ruby
before { request.path_info = "/" }

get "/" do
  "all requests end up here"
end
```

`request.body` 是一个 IO 或者 StringIO 对象：

```ruby
post "/api" do
  request.body.rewind  # 如果已经有人读了它
  data = JSON.parse request.body.read
  "Hello #{data['name']}!"
end
```

### 附件

你可以使用 `attachment` 辅助方法来告诉浏览器响应应当被写入磁盘而不是在浏览器中显示。

```ruby
get '/' do
  attachment
  "store it!"
end
```

你也可以传递给该方法一个文件名：

```ruby
get '/' do
  attachment "info.txt"
  "store it!"
end
```

### 处理日期和时间

Sinatra 提供了一个 `time_for` 辅助方法，其目的是根据给定的值生成 Time 对象。
该方法也能够转换 `DateTime`、`Date` 和类似的类：

```ruby
get '/' do
  pass if Time.now > time_for('Dec 23, 2012')
  "still time"
end
```

`expires`、`last_modified` 和类似方法都在内部使用了该方法。
因此，通过在应用中重写 `time_for` 方法，你可以轻松地扩展这些方法的行为：

```ruby
helpers do
  def time_for(value)
    case value
    when :yesterday then Time.now - 24*60*60
    when :tomorrow then Time.now + 24*60*60
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

### 查找模板文件

`find_template` 辅助方法用于在渲染时查找模板文件：

```ruby
find_template settings.views, 'foo', Tilt[:haml] do |file|
  puts "could be #{file}"
end
```

这其实并不是很有用，除非你需要重载这个方法来实现你自己的查找机制。
比如，如果你想使用不只一个视图目录：

```ruby
set :views, ['views', 'templates']

helpers do
  def find_template(views, name, engine, &block)
    Array(views).each { |v| super(v, name, engine, &block) }
  end
end
```

另一个例子是对不同的引擎使用不同的目录:

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

你可以很容易地封装成一个扩展，然后与他人分享！

请注意 `find_template` 并不会检查文件是否存在，而是为任何可能的路径调用传入的代码块。
这并不会导致性能问题，因为 `render` 会在找到文件的时候马上使用 `break`。
同样的，模板的路径（和内容）会在 development 以外的模式下被缓存。
你应该时刻提醒自己这一点， 如果你真的想写一个非常疯狂的方法的话。

## 配置

在启动时运行一次，在任何环境下都是如此：

```ruby
configure do
  # 设置一个选项
  set :option, 'value'

  # 设置多个选项
  set :a => 1, :b => 2

  # 等同于 `set :option, true`
  enable :option

  # 等同于 `set :option, false`
  disable :option

  # 也可以用代码块做动态设置
  set(:css_dir) { File.join(views, 'css') }
end
```

只有当环境 (`RACK_ENV` 环境变量) 被设定为 `:production` 时才运行：

```ruby
configure :production do
  ...
end
```

当环境被设定为 `:production` 或者 `:test` 时运行：

```ruby
configure :production, :test do
  ...
end
```

你可以用 `settings` 访问这些配置项：

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

### 配置攻击防护

Sinatra 使用 [Rack::Protection](https://github.com/sinatra/rack-protection#readme)
来抵御常见的攻击。你可以轻易地禁用该行为（但这会大大增加应用被攻击的概率）。

```ruby
disable :protection
```

为了绕过某单层防护，可以设置 `protection` 为一个选项 hash：

```ruby
set :protection, :except => :path_traversal
```

你可以传入一个数组，以禁用一系列防护措施：

```ruby
set :protection, :except => [:path_traversal, :session_hijacking]
```

默认地，如果 `:sessions` 是启用的，Sinatra 只会使用基于会话的防护措施。
当然，有时你可能想根据自己的需要设置会话。
在这种情况下，你可以通过传入 `:session` 选项来开启基于会话的防护。

```ruby
use Rack::Session::Pool
set :protection, :session => true
```

### 可选的设置

<dl>
  <dt>absolute_redirects</dt>
  <dd>
    如果被禁用，Sinatra 会允许使用相对路径重定向。
    然而这样的话，Sinatra 就不再遵守 RFC 2616 (HTTP 1.1), 该协议只允许绝对路径重定向。
  </dd>
  <dd>
    如果你的应用运行在一个未恰当设置的反向代理之后，你需要启用这个选项。
    注意 <tt>url</tt> 辅助方法仍然会生成绝对 URL，除非你传入<tt>false</tt> 作为第二参数。
  </dd>
  <dd>默认禁用。</dd>

  <dt>add_charset</dt>
  <dd>
    设置 <tt>content_type</tt> 辅助方法会自动为媒体类型加上字符集信息。
    你应该添加而不是覆盖这个选项:
    <tt>settings.add_charset << "application/foobar"</tt>
  </dd>

  <dt>app_file</dt>
  <dd>
    主应用文件的路径，用来检测项目的根路径， views 和 public 文件夹和内联模板。
  </dd>

  <dt>bind</dt>
  <dd>
    绑定的 IP 地址 (默认: <tt>0.0.0.0</tt>，开发环境下为 <tt>localhost</tt>)。
    仅对于内置的服务器有用。
  </dd>

  <dt>default_encoding</dt>
  <dd>默认编码 (默认为 <tt>"utf-8"</tt>)。</dd>

  <dt>dump_errors</dt>
  <dd>在日志中显示错误。</dd>

  <dt>environment</dt>
  <dd>
    当前环境，默认是 <tt>ENV['RACK_ENV']</tt>，
    或者 <tt>"development"</tt> (如果 ENV['RACK_ENV'] 不可用)。
  </dd>

  <dt>logging</dt>
  <dd>使用 logger。</dd>

  <dt>lock</dt>
  <dd>对每一个请求放置一个锁，只使用进程并发处理请求。</dd>
  <dd>如果你的应用不是线程安全则需启动。默认禁用。</dd>

  <dt>method_override</dt>
  <dd>
    使用 <tt>_method</tt> 魔法，以允许在不支持的浏览器中在使用 put/delete 方法提交表单。
  </dd>

  <dt>port</dt>
  <dd>监听的端口号。只对内置服务器有用。</dd>

  <dt>prefixed_redirects</dt>
  <dd>
    如果没有使用绝对路径，是否添加 <tt>request.script_name</tt> 到重定向请求。
    如果添加，<tt>redirect '/foo'</tt> 会和 <tt>redirect to('/foo')</tt> 相同。
    默认禁用。
  </dd>

  <dt>protection</dt>
  <dd>是否启用网络攻击防护。参见上面的保护部分</dd>

  <dt>public_dir</dt>
  <dd>public_folder 的别名。见下文。</dd>

  <dt>public_folder</dt>
  <dd>
    public 文件存放的路径。只有启用了静态文件服务（见下文的 <tt>static</tt>）才会使用。
    如果未设置，默认从 <tt>app_file</tt> 推断。
  </dd>

  <dt>reload_templates</dt>
  <dd>
    是否每个请求都重新载入模板。在开发模式下开启。
  </dd>

  <dt>root</dt>
  <dd>到项目根目录的路径。默认从 <tt>app_file</tt> 设置推断。</dd>

  <dt>raise_errors</dt>
  <dd>
    抛出异常（会停止应用）。
    当 <tt>environment</tt> 设置为 <tt>"test"</tt> 时会默认开启，其它环境下默认禁用。
  </dd>

  <dt>run</dt>
  <dd>如果启用，Sinatra 会负责 web 服务器的启动。若使用 rackup 或其他方式则不要启用。</dd>

  <dt>running</dt>
  <dd>内置的服务器在运行吗？ 不要修改这个设置！</dd>

  <dt>server</dt>
  <dd>服务器，或用于内置服务器的服务器列表。顺序表明了优先级，默认顺序依赖 Ruby 实现。</dd>

  <dt>sessions</dt>
  <dd>
    使用 <tt>Rack::Session::Cookie</tt>，启用基于 cookie 的会话。
    查看“使用会话”部分以获得更多信息。
  </dd>

  <dt>show_exceptions</dt>
  <dd>
    当有异常发生时，在浏览器中显示一个 stack trace。
    当 <tt>environment</tt> 设置为 <tt>"development"</tt> 时，默认启用，
    否则默认禁用。
  </dd>
  <dd>
    也可以设置为 <tt>:after_handler</tt>，
    这会在浏览器中显示 stack trace 之前触发应用级别的错误处理。
  </dd>

  <dt>static</dt>
  <dd>决定 Sinatra 是否服务静态文件。</dd>
  <dd>当服务器能够自行服务静态文件时，会禁用。</dd>
  <dd>禁用会增强性能。</dd>
  <dd>在经典风格中默认启用，在模块化应用中默认禁用。</dd>

  <dt>static_cache_control</dt>
  <dd>
    当 Sinatra 提供静态文件服务时，设置此选项为响应添加 <tt>Cache-Control</tt> 首部。
    使用 <tt>cache_control</tt> 辅助方法。默认禁用。
  </dd>
  <dd>
    当设置多个值时使用数组：
    <tt>set :static_cache_control, [:public, :max_age => 300]</tt>
  </dd>

  <dt>threaded</dt>
  <dd>
    若设置为 <tt>true</tt>，会告诉 Thin 使用 <tt>EventMachine.defer</tt> 处理请求。
  </dd>

  <dt>traps</dt>
  <dd>Sinatra 是否应该处理系统信号。</dd>

  <dt>views</dt>
  <dd>views 文件夹的路径。若未设置则会根据 <tt>app_file</tt> 推断。</dd>

  <dt>x_cascade</dt>
  <dd>若没有路由匹配，是否设置 X-Cascade 首部。默认为 <tt>true</tt>。</dd>
</dl>

## 环境

Sinatra 中有三种预先定义的环境："development"、"production" 和 "test"。
环境可以通过 `RACK_ENV` 环境变量设置。默认值为 "development"。
在开发环境下，每次请求都会重新加载所有模板，
特殊的 `not_found` 和 `error` 错误处理器会在浏览器中显示 stack trace。
在测试和生产环境下，模板默认会缓存。

在不同的环境下运行，设置 `RACK_ENV` 环境变量：

```shell
RACK_ENV=production ruby my_app.rb
```

可以使用预定义的三种方法： `development?`、`test?` 和 `production?` 来检查当前环境：

```ruby
get '/' do
  if settings.development?
    "development!"
  else
    "not development"
  end
end
```

## 错误处理

错误处理器在与路由和 before 过滤器相同的上下文中运行，
这意味着你可以使用许多好东西，比如 `haml`, `erb`, `halt`，等等。

### 未找到

当一个 `Sinatra::NotFound` 错误被抛出时，或者当响应的状态码是 404 时，
会调用 `not_found` 处理器：

```ruby
not_found do
  'This is nowhere to be found.'
end
```

### 错误

在任何路由代码块或过滤器抛出异常时，会调用 `error` 处理器。
但注意在开发环境下只有将 show exceptions 项设置为 `:after_handler` 时，才会生效。

```ruby
set :show_exceptions, :after_handler
```

可以用 Rack 变量 `sinatra.error` 访问异常对象：

```ruby
error do
  'Sorry there was a nasty error - ' + env['sinatra.error'].message
end
```

自定义错误：

```ruby
error MyCustomError do
  'So what happened was...' + env['sinatra.error'].message
end
```

当下面的代码执行时：

```ruby
get '/' do
  raise MyCustomError, 'something bad'
end
```

你会得到错误信息：

```
So what happened was... something bad
```

或者，你也可以为状态码设置错误处理器：

```ruby
error 403 do
  'Access forbidden'
end

get '/secret' do
  403
end
```

或者为某个范围内的状态码统一设置错误处理器：

```ruby
error 400..510 do
  'Boom'
end
```

在开发环境下，Sinatra会使用特殊的 `not_found` 和 `error` 处理器，
以便在浏览器中显示美观的 stack traces 和额外的调试信息。

## Rack 中间件

Sinatra 依赖 [Rack](http://rack.github.io/), 一个面向 Ruby 网络框架的最小化标准接口。
Rack 最有趣的功能之一是支持“中间件”——位于服务器和你的应用之间的组件，
它们监控或操作 HTTP 请求/响应以提供多种常用功能。

Sinatra 通过顶层的 `use` 方法，让建立 Rack 中间件管道异常简单：

```ruby
require 'sinatra'
require 'my_custom_middleware'

use Rack::Lint
use MyCustomMiddleware

get '/hello' do
  'Hello World'
end
```

`use` 的语义和在  [Rack::Builder](http://www.rubydoc.info/github/rack/rack/master/Rack/Builder)
DSL (在 rackup 文件中最频繁使用)中定义的完全一样。例如，`use` 方法接受
多个/可变参数，以及代码块：

```ruby
use Rack::Auth::Basic do |username, password|
  username == 'admin' && password == 'secret'
end
```

Rack 拥有有多种标准中间件，用于日志、调试、URL 路由、认证和会话处理。
根据配置，Sinatra 可以自动使用这里面的许多组件，
所以你一般不需要显式地 `use` 它们。

你可以在 [rack](https://github.com/rack/rack/tree/master/lib/rack)、
[rack-contrib](https://github.com/rack/rack-contrib#readm) 或
[Rack wiki](https://github.com/rack/rack/wiki/List-of-Middleware)
中找到有用的中间件。

## 测试

可以使用任何基于 Rack 的测试程序库或者框架来编写Sinatra的测试。
推荐使用 [Rack::Test](http://www.rubydoc.info/github/brynary/rack-test/master/frames)：

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

注意：如果你使用 Sinatra 的模块化风格，应该用你应用的类名替代 `Sinatra::Application`。

## Sinatra::Base - 中间件、库和模块化应用

在顶层定义你的应用很适合微型项目，
但是在构建可复用的组件（如 Rack 中间件、Rails metal、带服务器组件的库或 Sinatra 扩展）时，
却有相当大的缺陷。
顶层 DSL 认为你采用的是微型应用风格的配置 (例如：唯一应用文件、
`./public` 和 `./views` 目录、日志、异常细节页面等）。
如果你的项目不采用微型应用风格，应该使用 `Sinatra::Base`：

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

Sinatra::Base 的子类可以使用的方法实际上就是顶层 DSL 中可以使用的方法。
大部分顶层应用可以通过两方面的改变转换为 Sinatra::Base 组件：

* 你的文件应当引入 `sinatra/base` 而不是 `sinatra`；
否则，Sinatra 的所有 DSL 方法将会被导入主命名空间。

* 把应用的路由、错误处理器、过滤器和选项放在一个 Sinatra::Base 的子类中。

`Sinatra::Base` 是一个白板。大部分选项（包括内置的服务器）默认是禁用的。
可以参考[配置](http://www.sinatrarb.com/configuration.html)
以查看可用选项的具体细节和它们的行为。如果你想让你的应用更像顶层定义的应用（即经典风格），
你可以继承 `Sinatra::Applicaiton`。

```ruby
require 'sinatra/base'

class MyApp < Sinatra::Application
  get '/' do
    'Hello world!'
  end
end
```

### 模块化风格 vs. 经典风格

与通常的认识相反，经典风格并没有任何错误。
如果它适合你的应用，你不需要切换到模块化风格。

与模块化风格相比，经典风格的主要缺点在于，每个 Ruby 进程只能有一个 Sinatra 应用。
如果你计划使用多个 Sinatra 应用，应该切换到模块化风格。
你也完全可以混用模块化风格和经典风格。

如果从一种风格转换到另一种，你需要注意默认设置中的一些细微差别：

<table>
  <tr>
    <th>设置</th>
    <th>经典风格</th>
    <th>模块化风格</th>
    <th>模块化风格</th>
  </tr>

  <tr>
    <td>app_file</td>
    <td>加载 sinatra 的文件</td>
    <td>继承 Sinatra::Base 的文件</td>
    <td>继承 Sinatra::Application 的文件</td>
  </tr>

  <tr>
    <td>run</td>
    <td>$0 == app_file</td>
    <td>false</td>
    <td>false</td>
  </tr>

  <tr>
    <td>logging</td>
    <td>true</td>
    <td>false</td>
    <td>true</td>
  </tr>

  <tr>
    <td>method_override</td>
    <td>true</td>
    <td>false</td>
    <td>true</td>
  </tr>

  <tr>
    <td>inline_templates</td>
    <td>true</td>
    <td>false</td>
    <td>true</td>
  </tr>

  <tr>
    <td>static</td>
    <td>true</td>
    <td>File.exist?(public_folder)</td>
    <td>true</td>
  </tr>
</table>

### 运行一个模块化应用

模块化应用的启动有两种常见方式，其中之一是使用 `run!` 方法主动启动:

```ruby
# my_app.rb
require 'sinatra/base'

class MyApp < Sinatra::Base
  # ... 这里是应用代码 ...

  # 如果直接执行该文件，那么启动服务器
  run! if app_file == $0
end
```

执行该文件就会启动服务器：

```shell
ruby my_app.rb
```

另一种方式是使用 `config.ru` 文件，这种方式允许你使用任何 Rack 处理器：

```ruby
# config.ru （用 rackup 启动）
require './my_app'
run MyApp
```

运行：

```shell
rackup -p 4567
```

### 使用 config.ru 运行经典风格的应用

编写你的应用:

```ruby
# app.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

添加相应的 `config.ru`：

```ruby
require './app'
run Sinatra::Application
```

### 何时使用 config.ru？

下列情况，推荐使用 `config.ru`：

* 部署时使用不同的 Rack 处理器 (Passenger、Unicorn、Heroku 等)。
* 使用多个 `Sinatra::Base` 的子类。
* 把 Sinatra 当作中间件使用，而非端点。

**你不必仅仅因为想使用模块化风格而切换到 `config.ru`，同样的，
你也不必仅仅因为要运行 `config.ru` 而切换到模块化风格。**

### 把 Sinatra 当作中间件使用

Sinatra 可以使用其它 Rack 中间件，
反过来，任何 Sinatra 应用程序自身都可以被当作中间件，添加到任何 Rack 端点前面。
此端点可以是任何 Sinatra 应用，或任何基于 Rack 的应用程序 (Rails/Ramaze/Camping/...)：

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
  # 中间件的执行发生在 before 过滤器之前
  use LoginScreen

  before do
    unless session['user_name']
      halt "Access denied, please <a href='/login'>login</a>."
    end
  end

  get('/') { "Hello #{session['user_name']}." }
end
```

### 创建动态应用

有时你希望在运行时创建新应用，而不必把应用预先赋值给常量。这时可以使用 `Sinatra.new`：

```ruby
require 'sinatra/base'
my_app = Sinatra.new { get('/') { "hi" } }
my_app.run!
```

`Sinatra.new` 接受一个可选的参数，表示要继承的应用：

```ruby
# config.ru (用 rackup 启动)
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

当你测试 Sinatra 扩展或在自己的类库中使用 Sinatra 时，这非常有用。

这也让把 Sinatra 当作中间件使用变得极其容易：

```ruby
require 'sinatra/base'

use Sinatra do
  get('/') { ... }
end

run RailsProject::Application
```

## 作用域和绑定

当前作用域决定了可以使用的方法和变量。

### 应用/类作用域

每个 Sinatra 应用都对应 `Sinatra::Base` 类的一个子类。
如果你在使用顶层 DSL (`require 'sinatra'`)，那么这个类就是 `Sinatra::Application`，
否则该类是你显式创建的子类。
在类层面，你可以使用 `get` 或 `before` 这样的方法，
但不能访问 `request` 或 `session` 对象, 因为对于所有的请求，只有单一的应用类。

通过 `set` 创建的选项是类方法：

```ruby
class MyApp < Sinatra::Base
  # 嘿，我在应用作用域！
  set :foo, 42
  foo # => 42

  get '/foo' do
    # 嘿，我已经不在应用作用域了！
  end
end
```

下列位置绑定的是应用作用域：

* 应用类内部
* 通过扩展定义的方法内部
* 传递给 `helpers` 方法的代码块内部
* 作为 `set` 值的 procs/blocks 内部
* 传递给 `Sinatra.new` 的代码块内部

你可以这样访问变量域对象（应用类）：
* 通过传递给 configure 代码块的对象 (`configure { |c| ... }`)
* 在请求作用域中使用 `settings`

### 请求/实例作用域

对于每个请求，Sinatra 会创建应用类的一个新实例。所有的处理器代码块都在该实例对象的作用域中运行。
在该作用域中， 你可以访问 `request` 和 `session` 对象，
或调用渲染方法（如 `erb`、`haml`）。你可以在请求作用域中通过 `settings` 辅助方法
访问应用作用域：

```ruby
class MyApp < Sinatra::Base
  # 嘿，我在应用作用域!
  get '/define_route/:name' do
    # '/define_route/:name' 的请求作用域
    @value = 42

    settings.get("/#{params['name']}") do
      # "/#{params['name']}" 的请求作用域
      @value # => nil (并不是同一个请求)
    end

    "Route defined!"
  end
end
```

以下位置绑定的是请求作用域：

* get、head、post、put、delete、options、patch、link 和 unlink 代码块内部
* before 和 after 过滤器内部
* 辅助方法内部
* 模板/视图内部

### 代理作用域

代理作用域只是把方法转送到类作用域。
然而，它与类作用域的行为并不完全相同, 因为你并不能在代理作用域获得类的绑定。
只有显式地标记为供代理使用的方法才是可用的，
而且你不能和类作用域共享变量/状态。(解释：你有了一个不同的 `self`)。
你可以通过调用 `Sinatra::Delegator.delegate :method_name` 显式地添加方法代理。

以下位置绑定的是代理变量域：
* 顶层绑定，如果你执行了 `require "sinatra"`
* 扩展了 `Sinatra::Delegator` 这一 mixin 的对象内部

自己在这里看一下源码：[Sinatra::Delegator
mixin](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/base.rb#L1609-1633)
已经
[被扩展进了 main 对象](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/main.rb#L28-30)。

## 命令行

可以直接运行 Sinatra 应用：

```shell
ruby myapp.rb [-h] [-x] [-e ENVIRONMENT] [-p PORT] [-o HOST] [-s HANDLER]
```

选项是：

```
-h # 显示帮助
-p # 设置端口号 (默认是 4567)
-o # 设定主机名 (默认是 0.0.0.0)
-e # 设置环境 (默认是 development)
-s # 声明 rack 服务器/处理器 (默认是 thin)
-x # 打开互斥锁 (默认是 off)
```

### 多线程

_根据 Konstantin 的 [这个 StackOverflow 答案] [so-answer] 改写_

Sinatra 本身并不使用任何并发模型，而是将并发的任务留给底层的
Rack 处理器（服务器），如 Thin、Puma 或 WEBrick。Sinatra 本身是线程安全的，所以
Rack 处理器使用多线程并发模型并无任何问题。这意味着在启动服务器时，你必须指定特定
Rack 处理器的正确调用方法。
下面的例子展示了如何启动一个多线程的 Thin 服务器：

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

启动服务器的命令是：

```shell
thin --threaded start
```


[so-answer]: http://stackoverflow.com/questions/6278817/is-sinatra-multi-threaded/6282999#6282999)

## 必要条件

以下 Ruby 版本受官方支持:
<dl>
  <dt>Ruby 1.8.7</dt>
  <dd>
    Sinatra 完全支持 1.8.7，但是，除非必要，我们推荐你升级或者切换到
    JRuby 或 Rubinius。Sinatra 2.0 之前都不会取消对 1.8.7
    的支持。Ruby 1.8.6 目前已不受支持。
  </dd>

  <dt>Ruby 1.9.2</dt>
  <dd>
    Sinatra 完全支持 1.9.2。
    不要使用 1.9.2p0，它在运行 Sinatra 程序时会产生 segmentation faults 错误。
    至少在 Sinatra 1.5 发布之前，官方对 1.9.2 的支持仍会继续。
  </dd>

  <dt>Ruby 1.9.3</dt>
  <dd>
    Sinatra 完全支持并推荐使用 1.9.3。请注意从更早的版本迁移到 1.9.3 会使所有的会话失效。
    直到 Sinatra 2.0 发布之前，官方仍然会支持 1.9.3。
  </dd>

  <dt>Ruby 2.x</dt>
  <dd>
    Sinatra 完全支持并推荐使用 2.x。目前尚无停止支持 2.x 的计划。
  </dd>

  <dt>Rubinius</dt>
  <dd>
    Sinatra 官方支持 Rubinius (Rubinius >= 2.x)。推荐 <tt>gem install puma</tt>。
  </dd>

  <dt>JRuby</dt>
  <dd>
    Sinatra 官方支持 JRuby 的最新稳定版本，但不推荐在 JRuby 上使用 C 扩展。
    推荐 <tt>gem install trinidad</tt>。
  </dd>
</dl>

我们也在时刻关注新的 Ruby 版本。

以下 Ruby 实现不受 Sinatra 官方支持，但可以运行 Sinatra：

* 老版本 JRuby 和 Rubinius
* Ruby 企业版   
* MacRuby、Maglev、IronRuby
* Ruby 1.9.0 和 1.9.1 （不推荐使用）

不受官方支持的意思是，如果仅在不受支持的 Ruby 实现上发生错误，我们认为不是我们的问题，而是该实现的问题。

我们同时也针对 ruby-head （MRI 的未来版本）运行 CI，但由于 ruby-head 一直处在变化之中，
我们不能作任何保证。我们期望完全支持未来的 2.x 版本。

Sinatra 应该会运行在任何支持上述 Ruby 实现的操作系统上。

如果你使用 MacRuby，你应该 `gem install control_tower`。

Sinatra 目前不支持 Cardinal、SmallRuby、BlueRuby 或其它 1.8.7 之前的 Ruby 版本。

## 紧跟前沿

如果你想使用 Sinatra 的最新代码，请放心使用 master 分支来运行你的程序，它是相当稳定的。

我们也会不定期推出 prerelease gems，所以你也可以运行

```shell
gem install sinatra --pre
```

来获得最新的特性。

### 通过 Bundler 使用 Sinatra

如果你想在应用中使用最新的 Sinatra，推荐使用 [Bundler](http://bundler.io)。

首先，安装 Bundler，如果你还没有安装的话：

```shell
gem install bundler
```

然后，在你的项目目录下创建一个 `Gemfile`：

```ruby
source 'https://rubygems.org'
gem 'sinatra', :github => "sinatra/sinatra"

# 其它依赖
gem 'haml'                    # 假如你使用 haml
gem 'activerecord', '~> 3.0'  # 也许你还需要 ActiveRecord 3.x
```

请注意你必须在 `Gemfile` 中列出应用的所有依赖项。
然而， Sinatra 的直接依赖项 (Rack 和 Tilt) 则会被 Bundler 自动获取和添加。

现在你可以这样运行你的应用:

```shell
bundle exec ruby myapp.rb
```

### 使用自己本地的 Sinatra

创建一个本地克隆，并通过 `$LOAD_PATH` 里的 `sinatra/lib` 目录运行你的应用：

```shell
cd myapp
git clone git://github.com/sinatra/sinatra.git
ruby -I sinatra/lib myapp.rb
```

为了在未来更新 Sinatra 源代码：

```shell
cd myapp/sinatra
git pull
```

### 全局安装

你可以自行编译 Sinatra gem：

```shell
git clone git://github.com/sinatra/sinatra.git
cd sinatra
rake sinatra.gemspec
rake install
```

如果你以 root 身份安装 gems，最后一步应该是：

```shell
sudo rake install
```

## 版本

Sinatra 遵循[语义化版本](http://semver.org)，无论是 SemVer 还是 SemVerTag。

## 更多资料

* [项目官网](http://www.sinatrarb.com/) - 更多文档、新闻和其它资源的链接。
* [贡献](http://www.sinatrarb.com/contributing) - 找到一个 bug？需要帮助？有了一个 patch？
* [问题追踪](https://github.com/sinatra/sinatra/issues)
* [Twitter](https://twitter.com/sinatra)
* [邮件列表](http://groups.google.com/group/sinatrarb/topics)
* IRC: [#sinatra](irc://chat.freenode.net/#sinatra) on http://freenode.net
* [Sinatra & Friends](https://sinatrarb.slack.com) on Slack，点击
[这里](https://sinatra-slack.herokuapp.com/) 获得邀请。
* [Sinatra Book](https://github.com/sinatra/sinatra-book/) Cookbook 教程
* [Sinatra Recipes](http://recipes.sinatrarb.com/) 社区贡献的实用技巧
* http://www.rubydoc.info/ 上[最新版本](http://www.rubydoc.info//gems/sinatra)或[当前 HEAD](http://www.rubydoc.info/github/sinatra/sinatra) 的 API 文档
* [CI 服务器](https://travis-ci.org/sinatra/sinatra)
