# Sinatra

*注）
本文書は英語から翻訳したものであり、その内容が最新でない場合もあります。最新の情報はオリジナルの英語版を参照して下さい。*

Sinatraは最小の労力でRubyによるWebアプリケーションを手早く作るための[DSL](https://ja.wikipedia.org/wiki/メインページドメイン固有言語)です。

```ruby
# myapp.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

gemをインストールし、

```shell
gem install sinatra
```

次のように実行します。

```shell
ruby myapp.rb
```

[http://localhost:4567](http://localhost:4567) を開きます。

ThinがあればSinatraはこれを利用するので、`gem install thin`することをお薦めします。

## 目次

* [Sinatra](#sinatra)
    * [目次](#目次)
    * [ルーティング(Routes)](#ルーティングroutes)
    * [条件(Conditions)](#条件conditions)
    * [戻り値(Return Values)](#戻り値return-values)
    * [カスタムルーティングマッチャー(Custom Route Matchers)](#カスタムルーティングマッチャーcustom-route-matchers)
    * [静的ファイル(Static Files)](#静的ファイルstatic-files)
    * [ビュー / テンプレート(Views / Templates)](#ビュー--テンプレートviews--templates)
        * [リテラルテンプレート(Literal Templates)](#リテラルテンプレートliteral-templates)
        * [利用可能なテンプレート言語](#利用可能なテンプレート言語)
            * [Haml テンプレート](#haml-テンプレート)
            * [Erb テンプレート](#erb-テンプレート)
            * [Builder テンプレート](#builder-テンプレート)
            * [Nokogiri テンプレート](#nokogiri-テンプレート)
            * [Sass テンプレート](#sass-テンプレート)
            * [SCSS テンプレート](#scss-テンプレート)
            * [Less テンプレート](#less-テンプレート)
            * [Liquid テンプレート](#liquid-テンプレート)
            * [Markdown テンプレート](#markdown-テンプレート)
            * [Textile テンプレート](#textile-テンプレート)
            * [RDoc テンプレート](#rdoc-テンプレート)
            * [AsciiDoc テンプレート](#asciidoc-テンプレート)
            * [Radius テンプレート](#radius-テンプレート)
            * [Markaby テンプレート](#markaby-テンプレート)
            * [RABL テンプレート](#rabl-テンプレート)
            * [Slim テンプレート](#slim-テンプレート)
            * [Creole テンプレート](#creole-テンプレート)
            * [MediaWiki テンプレート](#mediawiki-テンプレート)
            * [CoffeeScript テンプレート](#coffeescript-テンプレート)
            * [Stylus テンプレート](#stylus-テンプレート)
            * [Yajl テンプレート](#yajl-テンプレート)
            * [WLang テンプレート](#wlang-テンプレート)
        * [テンプレート内での変数へのアクセス](#テンプレート内での変数へのアクセス)
        * [`yield`を伴うテンプレートとネストしたレイアウト](#yieldを伴うテンプレートとネストしたレイアウト)
        * [インラインテンプレート(Inline Templates)](#インラインテンプレートinline-templates)
        * [名前付きテンプレート(Named Templates)](#名前付きテンプレートnamed-templates)
        * [ファイル拡張子の関連付け](#ファイル拡張子の関連付け)
        * [オリジナルテンプレートエンジンの追加](#オリジナルテンプレートエンジンの追加)
    * [フィルタ(Filters)](#フィルタfilters)
    * [ヘルパー(Helpers)](#ヘルパーhelpers)
        * [セッションの使用](#セッションの使用)
        * [停止(Halting)](#停止halting)
        * [パッシング(Passing)](#パッシングpassing)
        * [別ルーティングの誘発](#別ルーティングの誘発)
        * [ボディ、ステータスコードおよびヘッダの設定](#ボディステータスコードおよびヘッダの設定)
        * [ストリーミングレスポンス(Streaming Responses)](#ストリーミングレスポンスstreaming-responses)
        * [ロギング(Logging)](#ロギングlogging)
        * [MIMEタイプ(Mime Types)](#mimeタイプmime-types)
        * [URLの生成](#urlの生成)
        * [ブラウザリダイレクト(Browser Redirect)](#ブラウザリダイレクトbrowser-redirect)
        * [キャッシュ制御(Cache Control)](#キャッシュ制御cache-control)
        * [ファイルの送信](#ファイルの送信)
        * [リクエストオブジェクトへのアクセス](#リクエストオブジェクトへのアクセス)
        * [アタッチメント(Attachments)](#アタッチメントattachments)
        * [日付と時刻の取り扱い](#日付と時刻の取り扱い)
        * [テンプレートファイルの探索](#テンプレートファイルの探索)
    * [コンフィギュレーション(Configuration)](#コンフィギュレーションconfiguration)
        * [攻撃防御に対する設定](#攻撃防御に対する設定)
        * [利用可能な設定](#利用可能な設定)
    * [環境設定(Environments)](#環境設定environments)
    * [エラーハンドリング(Error Handling)](#エラーハンドリングerror-handling)
        * [Not Found](#not-found)
        * [エラー(Error)](#エラーerror)
    * [Rackミドルウェア(Rack Middleware)](#rackミドルウェアrack-middleware)
    * [テスト(Testing)](#テストtesting)
    * [Sinatra::Base - ミドルウェア、ライブラリおよびモジュラーアプリ](#sinatrabase---ミドルウェアライブラリおよびモジュラーアプリ)
        * [モジュラースタイル vs クラッシックスタイル](#モジュラースタイル-vs-クラッシックスタイル)
        * [モジュラーアプリケーションの提供](#モジュラーアプリケーションの提供)
        * [config.ruを用いたクラッシックスタイルアプリケーションの使用](#configruを用いたクラッシックスタイルアプリケーションの使用)
        * [config.ruはいつ使うのか？](#configruはいつ使うのか)
        * [Sinatraのミドルウェアとしての利用](#sinatraのミドルウェアとしての利用)
        * [動的なアプリケーションの生成](#動的なアプリケーションの生成)
    * [スコープとバインディング(Scopes and Binding)](#スコープとバインディングscopes-and-binding)
        * [アプリケーション/クラスのスコープ](#アプリケーションクラスのスコープ)
        * [リクエスト/インスタンスのスコープ](#リクエストインスタンスのスコープ)
        * [デリゲートスコープ](#デリゲートスコープ)
    * [コマンドライン](#コマンドライン)
        * [マルチスレッド](#マルチスレッド)
    * [必要環境](#必要環境)
    * [最新開発版](#最新開発版)
        * [Bundlerを使う場合](#bundlerを使う場合)
        * [直接組み込む場合](#直接組み込む場合)
        * [グローバル環境にインストールする場合](#グローバル環境にインストールする場合)
    * [バージョニング(Versioning)](#バージョニングversioning)
    * [参考文献](#参考文献)

## ルーティング(Routes)

Sinatraでは、ルーティングはHTTPメソッドとURLマッチングパターンがペアになっています。
ルーティングはブロックに結び付けられています。

```ruby
get '/' do
  .. 何か見せる ..
end

post '/' do
  .. 何か生成する ..
end

put '/' do
  .. 何か更新する ..
end

patch '/' do
  .. 何か修正する ..
end

delete '/' do
  .. 何か削除する ..
end

options '/' do
  .. 何か満たす ..
end

link '/' do
  .. 何かリンクを張る ..
end

unlink '/' do
  .. 何かアンリンクする ..
end
```

ルーティングは定義された順番にマッチします。
リクエストに最初にマッチしたルーティングが呼び出されます。

ルーティングのパターンは名前付きパラメータを含むことができ、
`params`ハッシュで取得できます。

```ruby
get '/hello/:name' do
  # "GET /hello/foo" と "GET /hello/bar" にマッチ
  # params['name'] は 'foo' か 'bar'
  "Hello #{params['name']}!"
end
```

また、ブロックパラメータで名前付きパラメータにアクセスすることもできます。

```ruby
get '/hello/:name' do |n|
  # "GET /hello/foo" と "GET /hello/bar" にマッチ
  # params['name'] は 'foo' か 'bar'
  # n が params['name'] を保持
  "Hello #{n}!"
end
```

ルーティングパターンはアスタリスク(すなわちワイルドカード)を含むこともでき、
`params['splat']` で取得できます。

```ruby
get '/say/*/to/*' do
  # /say/hello/to/world にマッチ
  params['splat'] # => ["hello", "world"]
end

get '/download/*.*' do
  # /download/path/to/file.xml にマッチ
  params['splat'] # => ["path/to/file", "xml"]
end
```

ここで、ブロックパラメータを使うこともできます。

```ruby
get '/download/*.*' do |path, ext|
  [path, ext] # => ["path/to/file", "xml"]
end
```

ルーティングを正規表現にマッチさせることもできます。

```ruby
get /\A\/hello\/([\w]+)\z/ do
  "Hello, #{params['captures'].first}!"
end
```

ここでも、ブロックパラメータが使えます。

```ruby
get %r{/hello/([\w]+)} do |c|
  "Hello, #{c}!"
end
```

ルーティングパターンは、オプショナルパラメータを取ることもできます。

```ruby
get '/posts/:format?' do
  # "GET /posts/" と "GET /posts/json", "GET /posts/xml" の拡張子などにマッチ
end
```

ところで、ディレクトリトラバーサル攻撃防御設定を無効にしないと（下記参照）、
ルーティングにマッチする前にリクエストパスが修正される可能性があります。

## 条件(Conditions)

ルーティングにはユーザエージェントのようなさまざまな条件を含めることができます。

```ruby
get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
  "Songbirdのバージョン #{params['agent'][0]}を使ってます。"
end

get '/foo' do
  # Songbird以外のブラウザにマッチ
end
```

ほかに`host_name`と`provides`条件が利用可能です。

```ruby
get '/', :host_name => /^admin\./ do
  "Adminエリアです。アクセスを拒否します!"
end

get '/', :provides => 'html' do
  haml :index
end

get '/', :provides => ['rss', 'atom', 'xml'] do
  builder :feed
end
```

独自の条件を定義することも簡単にできます。

```ruby
set(:probability) { |value| condition { rand <= value } }

get '/win_a_car', :probability => 0.1 do
  "あなたの勝ちです!"
end

get '/win_a_car' do
  "残念、あなたの負けです。"
end
```

複数の値を取る条件には、アスタリスクを使います。

```ruby
set(:auth) do |*roles|   # <- ここでアスタリスクを使う
  condition do
    unless logged_in? && roles.any? {|role| current_user.in_role? role }
      redirect "/login/", 303
    end
  end
end

get "/my/account/", :auth => [:user, :admin] do
  "アカウントの詳細"
end

get "/only/admin/", :auth => :admin do
  "ここは管理者だけ!"
end
```

## 戻り値(Return Values)

ルーティングブロックの戻り値は、HTTPクライアントまたはRackスタックでの次のミドルウェアに渡されるレスポンスボディを決定します。

これは大抵の場合、上の例のように文字列ですが、それ以外の値も使用することができます。

Rackレスポンス、Rackボディオブジェクト、HTTPステータスコードのいずれかとして妥当なオブジェクトであればどのようなオブジェクトでも返すことができます。

* 3つの要素を含む配列:
  `[ステータス(Fixnum), ヘッダ(Hash), レスポンスボディ(#eachに応答する)]`
* 2つの要素を含む配列:
  `[ステータス(Fixnum), レスポンスボディ(#eachに応答する)]`
* `#each`に応答するオブジェクト。通常はそのまま何も返さないが、
与えられたブロックに文字列を渡す。
* ステータスコードを表現する整数(Fixnum)

これにより、例えばストリーミングを簡単に実装することができます。

```ruby
class Stream
  def each
    100.times { |i| yield "#{i}\n" }
  end
end

get('/') { Stream.new }
```

後述する`stream`ヘルパーメソッドを使って、定型パターンを減らしつつストリーミングロジックをルーティングに埋め込むこともできます。

## カスタムルーティングマッチャー(Custom Route Matchers)

先述のようにSinatraはルーティングマッチャーとして、文字列パターンと正規表現を使うことをビルトインでサポートしています。しかしこれに留まらず、独自のマッチャーを簡単に定義することもできるのです。

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

ノート: この例はオーバースペックであり、以下のようにも書くことができます。

```ruby
get // do
  pass if request.path_info == "/index"
  # ...
end
```

または、否定先読みを使って:

```ruby
get %r{^(?!/index$)} do
  # ...
end
```


## 静的ファイル(Static Files)

静的ファイルは`./public`ディレクトリから配信されます。
`:public_folder`オプションを指定することで別の場所を指定することができます。

```ruby
set :public_folder, File.dirname(__FILE__) + '/static'
```

ノート: この静的ファイル用のディレクトリ名はURL中に含まれません。
例えば、`./public/css/style.css`は`http://example.com/css/style.css`でアクセスできます。

`Cache-Control`の設定をヘッダーへ追加するには`:static_cache_control`の設定(下記参照)を加えてください。

## ビュー / テンプレート(Views / Templates)

各テンプレート言語はそれ自身のレンダリングメソッドを通して展開されます。それらのメソッドは単に文字列を返します。

```ruby
get '/' do
  erb :index
end
```

これは、`views/index.erb`をレンダリングします。

テンプレート名を渡す代わりに、直接そのテンプレートの中身を渡すこともできます。

```ruby
get '/' do
  code = "<%= Time.now %>"
  erb code
end
```

テンプレートのレイアウトは第２引数のハッシュ形式のオプションをもとに表示されます。

```ruby
get '/' do
  erb :index, :layout => :post
end
```

これは、`views/post.erb`内に埋め込まれた`views/index.erb`をレンダリングします（デフォルトは`views/layout.erb`があればそれになります）。

Sinatraが理解できないオプションは、テンプレートエンジンに渡されることになります。


```ruby
get '/' do
  haml :index, :format => :html5
end
```

テンプレート言語ごとにオプションをセットすることもできます。

```ruby
set :haml, :format => :html5

get '/' do
  haml :index
end
```

レンダリングメソッドに渡されたオプションは`set`で設定されたオプションを上書きします。

利用可能なオプション:

<dl>
  <dt>locals</dt>
  <dd>
    ドキュメントに渡されるローカルのリスト。パーシャルに便利。
    例: <tt>erb "<%= foo %>", :locals => {:foo => "bar"}</tt>
  </dd>

  <dt>default_encoding</dt>
  <dd>
    文字エンコーディング（不確かな場合に使用される）。デフォルトは、<tt>settings.default_encoding</tt>。
  </dd>

  <dt>views</dt>
  <dd>
    テンプレートを読み出すビューのディレクトリ。デフォルトは、<tt>settings.views</tt>。
  </dd>

  <dt>layout</dt>
  <dd>
    レイアウトを使うかの指定(<tt>true</tt> または <tt>false</tt>)。値がシンボルの場合は、使用するテンプレートが指定される。例: <tt>erb :index, :layout => !request.xhr?</tt>
  </dd>

  <dt>content_type</dt>
  <dd>
    テンプレートが生成するContent-Type。デフォルトはテンプレート言語ごとに異なる。
  </dd>

  <dt>scope</dt>
  <dd>
    テンプレートをレンダリングするときのスコープ。デフォルトは、アプリケーションのインスタンス。これを変更した場合、インスタンス変数およびヘルパーメソッドが利用できなくなる。
  </dd>

  <dt>layout_engine</dt>
  <dd>
    レイアウトをレンダリングするために使用するテンプレートエンジン。レイアウトをサポートしない言語で有用。デフォルトはテンプレートに使われるエンジン。例: <tt>set :rdoc, :layout_engine => :erb</tt>
  </dd>

  <dt>layout_options</dt>
  <dd>
    レイアウトをレンダリングするときだけに使う特別なオプション。例:
    <tt>set :rdoc, :layout_options => { :views => 'views/layouts' }</tt>
  </dd>
</dl>

テンプレートは`./views`ディレクトリ下に配置されています。
他のディレクトリを使用する場合の例:

```ruby
set :views, settings.root + '/templates'
```

テンプレートはシンボルを使用して参照させることを覚えておいて下さい。
サブディレクトリでもこの場合は`:'subdir/template'`のようにします。
レンダリングメソッドは文字列が渡されると、それをそのまま文字列として出力するので、シンボルを使ってください。

### リテラルテンプレート(Literal Templates)

```ruby
get '/' do
  haml '%div.title Hello World'
end
```

これはそのテンプレート文字列をレンダリングします。

### 利用可能なテンプレート言語

いくつかの言語には複数の実装があります。使用する（そしてスレッドセーフにする）実装を指定するには、それを最初にrequireしてください。


```ruby
require 'rdiscount' # または require 'bluecloth'
get('/') { markdown :index }
```

#### Haml テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://haml.info/" title="haml">haml</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.haml</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>haml :index, :format => :html5</tt></td>
  </tr>
</table>


#### Erb テンプレート

<table>
  <tr>
    <td>依存</td>
    <td>
      <a href="http://www.kuwata-lab.com/erubis/" title="erubis">erubis</a>
      または erb (Rubyに同梱)
    </td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.erb</tt>, <tt>.rhtml</tt> or <tt>.erubis</tt> (Erubisだけ)</td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>erb :index</tt></td>
  </tr>
</table>

#### Builder テンプレート

<table>
  <tr>
    <td>依存</td>
    <td>
      <a href="https://github.com/jimweirich/builder" title="builder">builder</a>
    </td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.builder</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>builder { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

インラインテンプレート用にブロックを取ることもできます（例を参照）。

#### Nokogiri テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://www.nokogiri.org/" title="nokogiri">nokogiri</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.nokogiri</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>nokogiri { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

インラインテンプレート用にブロックを取ることもできます（例を参照）。


#### Sass テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.sass</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>sass :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>


#### Scss テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.scss</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>scss :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

#### Less テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://lesscss.org/" title="less">less</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.less</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>less :stylesheet</tt></td>
  </tr>
</table>

#### Liquid テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://liquidmarkup.org/" title="liquid">liquid</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.liquid</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>liquid :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

LiquidテンプレートからRubyのメソッド(`yield`を除く)を呼び出すことができないため、ほぼ全ての場合にlocalsを指定する必要があるでしょう。

#### Markdown テンプレート

<table>
  <tr>
    <td>依存</td>
    <td>
      次の何れか:
        <a href="https://github.com/davidfstr/rdiscount" title="RDiscount">RDiscount</a>,
        <a href="https://github.com/vmg/redcarpet" title="RedCarpet">RedCarpet</a>,
        <a href="http://deveiate.org/projects/BlueCloth" title="BlueCloth">BlueCloth</a>,
        <a href="http://kramdown.gettalong.org/" title="kramdown">kramdown</a>,
        <a href="https://github.com/bhollis/maruku" title="maruku">maruku</a>
    </td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.markdown</tt>, <tt>.mkd</tt> and <tt>.md</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>markdown :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

Markdownからメソッドを呼び出すことも、localsに変数を渡すこともできません。
それゆえ、他のレンダリングエンジンとの組み合わせで使うのが普通です。

```ruby
erb :overview, :locals => { :text => markdown(:introduction) }
```

ノート: 他のテンプレート内で`markdown`メソッドを呼び出せます。

```ruby
%h1 Hello From Haml!
%p= markdown(:greetings)
```

MarkdownからはRubyを呼ぶことができないので、Markdownで書かれたレイアウトを使うことはできません。しかしながら、`:layout_engine`オプションを渡すことでテンプレートのものとは異なるレンダリングエンジンをレイアウトのために使うことができます。


#### Textile テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://redcloth.org/" title="RedCloth">RedCloth</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.textile</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>textile :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

Textileからメソッドを呼び出すことも、localsに変数を渡すこともできません。
それゆえ、他のレンダリングエンジンとの組み合わせで使うのが普通です。

```ruby
erb :overview, :locals => { :text => textile(:introduction) }
```

ノート: 他のテンプレート内で`textile`メソッドを呼び出せます。

```ruby
%h1 Hello From Haml!
%p= textile(:greetings)
```

TexttileからはRubyを呼ぶことができないので、Textileで書かれたレイアウトを使うことはできません。しかしながら、`:layout_engine`オプションを渡すことでテンプレートのものとは異なるレンダリングエンジンをレイアウトのために使うことができます。

#### RDoc テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://rdoc.sourceforge.net/" title="RDoc">RDoc</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.rdoc</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>rdoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

RDocからメソッドを呼び出すことも、localsに変数を渡すこともできません。
それゆえ、他のレンダリングエンジンとの組み合わせで使うのが普通です。

```ruby
erb :overview, :locals => { :text => rdoc(:introduction) }
```

ノート: 他のテンプレート内で`rdoc`メソッドを呼び出せます。


```ruby
%h1 Hello From Haml!
%p= rdoc(:greetings)
```

RDocからはRubyを呼ぶことができないので、RDocで書かれたレイアウトを使うことはできません。しかしながら、`:layout_engine`オプションを渡すことでテンプレートのものとは異なるレンダリングエンジンをレイアウトのために使うことができます。

#### AsciiDoc テンプレート

<table>
 <tr>
   <td>依存</td>
   <td><a href="http://asciidoctor.org/" title="Asciidoctor">Asciidoctor</a></td>
 </tr>
 <tr>
   <td>ファイル拡張子</td>
   <td><tt>.asciidoc</tt>, <tt>.adoc</tt> and <tt>.ad</tt></td>
 </tr>
 <tr>
   <td>例</td>
   <td><tt>asciidoc :README, :layout_engine => :erb</tt></td>
 </tr>
</table>

AsciiDocテンプレートからRubyのメソッドを直接呼び出すことができないため、ほぼ全ての場合にlocalsを指定する必要があるでしょう。

#### Radius テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="https://github.com/jlong/radius" title="Radius">Radius</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.radius</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>radius :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

RadiusテンプレートからRubyのメソッドを直接呼び出すことができないため、ほぼ全ての場合にlocalsを指定する必要があるでしょう。


#### Markaby テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://markaby.github.io/" title="Markaby">Markaby</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.mab</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>markaby { h1 "Welcome!" }</tt></td>
  </tr>
</table>

インラインテンプレート用にブロックを取ることもできます（例を参照）。

#### RABL テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="https://github.com/nesquena/rabl" title="Rabl">Rabl</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.rabl</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>rabl :index</tt></td>
  </tr>
</table>

#### Slim テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="http://slim-lang.com/" title="Slim Lang">Slim Lang</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.slim</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>slim :index</tt></td>
  </tr>
</table>

#### Creole テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="https://github.com/minad/creole" title="Creole">Creole</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.creole</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>creole :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

Creoleからメソッドを呼び出すことも、localsに変数を渡すこともできません。
それゆえ、他のレンダリングエンジンとの組み合わせで使うのが普通です。

```ruby
erb :overview, :locals => { :text => creole(:introduction) }
```

ノート: 他のテンプレート内で`creole`メソッドを呼び出せます。

```ruby
%h1 Hello From Haml!
%p= creole(:greetings)
```

CreoleからはRubyを呼ぶことができないので、Creoleで書かれたレイアウトを使うことはできません。しかしながら、`:layout_engine`オプションを渡すことでテンプレートのものとは異なるレンダリングエンジンをレイアウトのために使うことができます。

#### MediaWiki テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="https://github.com/nricciar/wikicloth" title="WikiCloth">WikiCloth</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.mediawiki</tt> および <tt>.mw</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>mediawiki :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

MediaWikiのテンプレートは直接メソッドから呼び出したり、ローカル変数を通すことはできません。それゆえに、通常は別のレンダリングエンジンと組み合わせて利用します。

```ruby
erb :overview, :locals => { :text => mediawiki(:introduction) }
```

ノート: 他のテンプレートから部分的に`mediawiki`メソッドを呼び出すことも可能です。

#### CoffeeScript テンプレート

<table>
  <tr>
    <td>依存</td>
    <td>
      <a href="https://github.com/josh/ruby-coffee-script" title="Ruby CoffeeScript">
        CoffeeScript
      </a> および
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        JavaScriptの起動方法
      </a>
    </td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.coffee</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>coffee :index</tt></td>
  </tr>
</table>

#### Stylus テンプレート

<table>
  <tr>
    <td>依存</td>
    <td>
      <a href="https://github.com/forgecrafted/ruby-stylus" title="Ruby Stylus">
        Stylus
      </a> および
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        JavaScriptの起動方法
      </a>
    </td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.styl</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>stylus :index</tt></td>
  </tr>
</table>

Stylusテンプレートを使えるようにする前に、まず`stylus`と`stylus/tilt`を読み込む必要があります。

```ruby
require 'sinatra'
require 'stylus'
require 'stylus/tilt'

get '/' do
  stylus :example
end
```

#### Yajl テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="https://github.com/brianmario/yajl-ruby" title="yajl-ruby">yajl-ruby</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.yajl</tt></td>
  </tr>
  <tr>
    <td>例</td>
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


テンプレートのソースはRubyの文字列として評価され、その結果のJSON変数は`#to_json`を使って変換されます。

```ruby
json = { :foo => 'bar' }
json[:baz] = key
```

`:callback`および`:variable`オプションは、レンダリングされたオブジェクトを装飾するために使うことができます。

```ruby
var resource = {"foo":"bar","baz":"qux"}; present(resource);
```

#### WLang テンプレート

<table>
  <tr>
    <td>依存</td>
    <td><a href="https://github.com/blambeau/wlang/" title="wlang">wlang</a></td>
  </tr>
  <tr>
    <td>ファイル拡張子</td>
    <td><tt>.wlang</tt></td>
  </tr>
  <tr>
    <td>例</td>
    <td><tt>wlang :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

WLang内でのRubyメソッドの呼び出しは一般的ではないので、ほとんどの場合にlocalsを指定する必要があるでしょう。しかしながら、WLangで書かれたレイアウトは`yield`をサポートしています。

### テンプレート内での変数へのアクセス

テンプレートはルーティングハンドラと同じコンテキストの中で評価されます。ルーティングハンドラでセットされたインスタンス変数はテンプレート内で直接使うことができます。

```ruby
get '/:id' do
  @foo = Foo.find(params['id'])
  haml '%h1= @foo.name'
end
```

また、ローカル変数のハッシュで明示的に指定することもできます。

```ruby
get '/:id' do
  foo = Foo.find(params['id'])
  haml '%h1= bar.name', :locals => { :bar => foo }
end
```

このやり方は他のテンプレート内で部分テンプレートとして表示する時に典型的に使用されます。

### `yield`を伴うテンプレートとネストしたレイアウト

レイアウトは通常、`yield`を呼ぶ単なるテンプレートに過ぎません。
そのようなテンプレートは、既に説明した`:template`オプションを通して使われるか、または次のようなブロックを伴ってレンダリングされます。

```ruby
erb :post, :layout => false do
  erb :index
end
```

このコードは、`erb :index, :layout => :post`とほぼ等価です。

レンダリングメソッドにブロックを渡すスタイルは、ネストしたレイアウトを作るために最も役立ちます。

```ruby
erb :main_layout, :layout => false do
  erb :admin_layout do
    erb :user
  end
end
```

これはまた次のより短いコードでも達成できます。

```ruby
erb :admin_layout, :layout => :main_layout do
  erb :user
end
```

現在、次のレンダリングメソッドがブロックを取れます: `erb`, `haml`,
`liquid`, `slim `, `wlang`。
また汎用の`render`メソッドもブロックを取れます。


### インラインテンプレート(Inline Templates)

テンプレートはソースファイルの最後で定義することもできます。

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
%div.title Hello world!!!!!
```

ノート: Sinatraをrequireするソースファイル内で定義されたインラインテンプレートは自動的に読み込まれます。他のソースファイル内にインラインテンプレートがある場合には`enable :inline_templates`を明示的に呼んでください。

### 名前付きテンプレート(Named Templates)

テンプレートはトップレベルの`template`メソッドで定義することもできます。

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

「layout」というテンプレートが存在する場合、そのテンプレートファイルは他のテンプレートがレンダリングされる度に使用されます。`:layout => false`で個別に、または`set :haml, :layout => false`でデフォルトとして、レイアウトを無効にすることができます。

```ruby
get '/' do
  haml :index, :layout => !request.xhr?
end
```

### ファイル拡張子の関連付け

任意のテンプレートエンジンにファイル拡張子を関連付ける場合は、`Tilt.register`を使います。例えば、Textileテンプレートに`tt`というファイル拡張子を使いたい場合は、以下のようにします。

```ruby
Tilt.register :tt, Tilt[:textile]
```

### オリジナルテンプレートエンジンの追加

まず、Tiltでそのエンジンを登録し、次にレンダリングメソッドを作ります。

```ruby
Tilt.register :myat, MyAwesomeTemplateEngine

helpers do
  def myat(*args) render(:myat, *args) end
end

get '/' do
  myat :index
end
```

これは、`./views/index.myat`をレンダリングします。Tiltについての詳細は、https://github.com/rtomayko/tilt を参照してください。

## フィルタ(Filters)

beforeフィルタは、リクエストのルーティングと同じコンテキストで各リクエストの前に評価され、それによってリクエストとレスポンスを変更可能にします。フィルタ内でセットされたインスタンス変数はルーティングとテンプレートからアクセスすることができます。

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

afterフィルタは、リクエストのルーティングと同じコンテキストで各リクエストの後に評価され、それによってこれもリクエストとレスポンスを変更可能にします。beforeフィルタとルーティング内でセットされたインスタンス変数はafterフィルタからアクセスすることができます。

```ruby
after do
  puts response.status
end
```

ノート: `body`メソッドを使わずにルーティングから文字列を返すだけの場合、その内容はafterフィルタでまだ利用できず、その後に生成されることになります。

フィルタにはオプションとしてパターンを渡すことができ、この場合はリクエストのパスがパターンにマッチした場合にのみフィルタが評価されるようになります。

```ruby
before '/protected/*' do
  authenticate!
end

after '/create/:slug' do |slug|
  session[:last_slug] = slug
end
```

ルーティング同様、フィルタもまた条件を取ることができます。

```ruby
before :agent => /Songbird/ do
  # ...
end

after '/blog/*', :host_name => 'example.com' do
  # ...
end
```

## ヘルパー(Helpers)

トップレベルの`helpers`メソッドを使用してルーティングハンドラやテンプレートで使うヘルパーメソッドを定義できます。

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

あるいは、ヘルパーメソッドをモジュール内で個別に定義することもできます。

```ruby
module FooUtils
  def foo(name) "#{name}foo" end
end

module BarUtils
  def bar(name) "#{name}bar" end
end

helpers FooUtils, BarUtils
```

その効果は、アプリケーションクラスにモジュールをインクルードするのと同じです。


### セッションの使用

セッションはリクエスト間での状態維持のために使用されます。その起動により、ユーザセッションごとに一つのセッションハッシュが与えられます。

```ruby
enable :sessions

get '/' do
  "value = " << session[:value].inspect
end

get '/:value' do
  session[:value] = params['value']
end
```

ノート: `enable :sessions`は実際にはすべてのデータをクッキーに保持します。これは必ずしも期待通りのものにならないかもしれません（例えば、大量のデータを保持することでトラフィックが増大するなど）。Rackセッションミドルウェアの利用が可能であり、その場合は`enable :sessions`を呼ばずに、選択したミドルウェアを他のミドルウェアのときと同じようにして取り込んでください。

```ruby
use Rack::Session::Pool, :expire_after => 2592000

get '/' do
  "value = " << session[:value].inspect
end

get '/:value' do
  session[:value] = params['value']
end
```

セキュリティ向上のため、クッキー内のセッションデータはセッション秘密鍵(session secret)で署名されます。Sinatraによりランダムな秘密鍵が個別に生成されます。しかし、この秘密鍵はアプリケーションの立ち上げごとに変わってしまうので、すべてのアプリケーションのインスタンスで共有できる秘密鍵をセットしたくなるかもしれません。

```ruby
set :session_secret, 'super secret'
```

更に、設定変更をしたい場合は、`sessions`の設定においてオプションハッシュを保持することもできます。

```ruby
set :sessions, :domain => 'foo.com'
```

foo.comのサブドメイン上のアプリ間でセッションを共有化したいときは、代わりにドメインの前に *.* を付けます。

```ruby
set :sessions, :domain => '.foo.com'
```

### 停止(Halting)

フィルタまたはルーティング内で直ちにリクエストを止める場合

```ruby
halt
```

この際、ステータスを指定することもできます。

```ruby
halt 410
```

body部を指定することも、

```ruby
halt 'ここにbodyを書く'
```

ステータスとbody部を指定することも、

```ruby
halt 401, '立ち去れ!'
```

ヘッダを付けることもできます。

```ruby
halt 402, {'Content-Type' => 'text/plain'}, 'リベンジ'
```

もちろん、テンプレートを`halt`に結びつけることも可能です。

```ruby
halt erb(:error)
```

### パッシング(Passing)

ルーティングは`pass`を使って次のルーティングに飛ばすことができます。

```ruby
get '/guess/:who' do
  pass unless params['who'] == 'Frank'
  "見つかっちゃった!"
end

get '/guess/*' do
  "はずれです!"
end
```

ルーティングブロックからすぐに抜け出し、次にマッチするルーティングを実行します。マッチするルーティングが見当たらない場合は404が返されます。

### 別ルーティングの誘発

`pass`を使ってルーティングを飛ばすのではなく、他のルーティングを呼んだ結果を得たいというときがあります。これを実現するには`call`を使えばいいです。

```ruby
get '/foo' do
  status, headers, body = call env.merge("PATH_INFO" => '/bar')
  [status, headers, body.map(&:upcase)]
end

get '/bar' do
  "bar"
end
```

ノート: 先の例において、テストを楽にしパフォーマンスを改善するには、`"bar"`を単にヘルパーに移し、`/foo`および`/bar`から使えるようにするのがいいです。

リクエストが、その複製物でない同じアプリケーションのインスタンスに送られるようにしたいときは、`call`に代えて`call!`を使ってください。

`call`についての詳細はRackの仕様書を参照してください。


### ボディ、ステータスコードおよびヘッダの設定

ステータスコードおよびレスポンスボディを、ルーティングブロックの戻り値にセットすることが可能であり、これは推奨されています。しかし、あるケースでは実行フローの任意のタイミングでボディをセットしたくなるかもしれません。`body`ヘルパーメソッドを使えばそれができます。そうすると、それ以降、ボディにアクセスするためにそのメソッドを使うことができるようになります。

```ruby
get '/foo' do
  body "bar"
end

after do
  puts body
end
```

また、`body`にはブロックを渡すことができ、これはRackハンドラにより実行されることになります(これはストリーミングを実装するのに使われます。"戻り値"の項を参照してください。)

ボディと同様に、ステータスコードおよびヘッダもセットできます。

```ruby
get '/foo' do
  status 418
  headers \
    "Allow"   => "BREW, POST, GET, PROPFIND, WHEN",
    "Refresh" => "Refresh: 20; http://www.ietf.org/rfc/rfc2324.txt"
  body "I'm a tea pot!"
end
```

引数を伴わない`body`、`headers`、`status`などは、それらの現在の値にアクセスするために使えます。

### ストリーミングレスポンス(Streaming Responses)

レスポンスボディの部分を未だ生成している段階で、データを送り出したいということがあります。極端な例では、クライアントがコネクションを閉じるまでデータを送り続けたいことがあります。`stream`ヘルパーを使えば、独自ラッパーを作る必要はありません。

```ruby
get '/' do
  stream do |out|
    out << "それは伝 -\n"
    sleep 0.5
    out << " (少し待つ) \n"
    sleep 1
    out << "- 説になる！\n"
  end
end
```

これはストリーミングAPI、[Server Sent Events](https://w3c.github.io/eventsource/)の実装を可能にし、[WebSockets](https://en.wikipedia.org/wiki/WebSocket)の土台に使うことができます。また、一部のコンテンツが遅いリソースに依存しているときに、スループットを上げるために使うこともできます。

ノート: ストリーミングの挙動、特に並行リクエスト(cuncurrent requests)の数は、アプリケーションを提供するのに使われるWebサーバに強く依存します。いくつかのサーバは、ストリーミングを全くサポートしません。サーバがストリーミングをサポートしない場合、ボディは`stream`に渡されたブロックの実行が終了した後、一度に全部送られることになります。ストリーミングは、Shotgunを使った場合は全く動作しません。

オプション引数が`keep_open`にセットされている場合、ストリームオブジェクト上で`close`は呼ばれず、実行フローの任意の遅れたタイミングでユーザがこれを閉じることを可能にします。これはThinやRainbowsのようなイベント型サーバ上でしか機能しません。他のサーバでは依然ストリームは閉じられます。

```ruby
# ロングポーリング

set :server, :thin
connections = []

get '/subscribe' do
  # サーバイベントにおけるクライアントの関心を登録
  stream(:keep_open) do |out|
    connections << out
    # 死んでいるコネクションを排除
    connections.reject!(&:closed?)
  end
end

post '/message' do
  connections.each do |out|
    # クライアントへ新規メッセージ到着の通知
    out << params['message'] << "\n"

    # クライアントへの再接続の指示
    out.close
  end

  # 肯定応答
  "message received"
end
```

### ロギング(Logging)

リクエストスコープにおいて、`logger`ヘルパーは`Logger`インスタンスを作り出します。


```ruby
get '/' do
  logger.info "loading data"
  # ...
end
```

このロガーは、自動でRackハンドラのロギング設定を参照します。ロギングが無効(disabled)にされている場合、このメソッドはダミーオブジェクトを返すので、ルーティングやフィルタにおいて特に心配することはありません。

ノート: ロギングは、`Sinatra::Application`に対してのみデフォルトで有効にされているので、`Sinatra::Base`を継承している場合は、ユーザがこれを有効化する必要があります。

```ruby
class MyApp < Sinatra::Base
  configure :production, :development do
    enable :logging
  end
end
```

ロギングミドルウェアが設定されてしまうのを避けるには、`logging`設定を`nil`にセットします。しかしこの場合、`logger`が`nil`を返すことを忘れないように。よくあるユースケースは、オリジナルのロガーをセットしたいときです。Sinatraは、とにかく`env['rack.logger']`で見つかるものを使います。

### MIMEタイプ(Mime Types)

`send_file`か静的ファイルを使う時、SinatraがMIMEタイプを理解できない場合があります。その時は `mime_type` を使ってファイル拡張子毎に登録して下さい。

```ruby
configure do
  mime_type :foo, 'text/foo'
end
```

これは`content_type`ヘルパーで利用することができます:

```ruby
get '/' do
  content_type :foo
  "foo foo foo"
end
```

### URLの生成

URLを生成するためには`url`ヘルパーメソッドが使えます。Hamlではこのようにします。

```ruby
%a{:href => url('/foo')} foo
```

これはリバースプロキシおよびRackルーティングを、それらがあれば考慮に入れます。

このメソッドには`to`というエイリアスがあります(以下の例を参照)。

### ブラウザリダイレクト(Browser Redirect)

`redirect` ヘルパーメソッドを使うことで、ブラウザをリダイレクトさせることができます。

```ruby
get '/foo' do
  redirect to('/bar')
end
```

他に追加されるパラメータは、`halt`に渡される引数と同様に取り扱われます。

```ruby
redirect to('/bar'), 303
redirect 'http://www.google.com/', 'wrong place, buddy'
```

また、`redirect back`を使えば、簡単にユーザが来たページへ戻るリダイレクトを作れます。

```ruby
get '/foo' do
  "<a href='/bar'>do something</a>"
end

get '/bar' do
  do_something
  redirect back
end
```

redirectに引数を渡すには、それをクエリーに追加するか、


```ruby
redirect to('/bar?sum=42')
```

または、セッションを使います。

```ruby
enable :sessions

get '/foo' do
  session[:secret] = 'foo'
  redirect to('/bar')
end

get '/bar' do
  session[:secret]
end
```

### キャッシュ制御(Cache Control)

ヘッダを正しく設定することが、適切なHTTPキャッシングのための基礎となります。

キャッシュ制御ヘッダ(Cache-Control header)は、次のように簡単に設定できます。

```ruby
get '/' do
  cache_control :public
  "キャッシュしました!"
end
```

ヒント: キャッシングをbeforeフィルタ内で設定します。

```ruby
before do
  cache_control :public, :must_revalidate, :max_age => 60
end
```

`expires`ヘルパーを対応するヘッダに使っている場合は、キャッシュ制御は自動で設定されます。

```ruby
before do
  expires 500, :public, :must_revalidate
end
```

キャッシュを適切に使うために、`etag`または`last_modified`を使うことを検討してください。これらのヘルパーを、重い仕事をさせる *前* に呼ぶことを推奨します。そうすれば、クライアントが既にキャッシュに最新版を持っている場合はレスポンスを直ちに破棄するようになります。

```ruby
get '/article/:id' do
  @article = Article.find params['id']
  last_modified @article.updated_at
  etag @article.sha1
  erb :article
end
```

また、[weak ETag](https://ja.wikipedia.org/wiki/HTTP_ETag#Strong_and_weak_validation)を使うこともできます。

```ruby
etag @article.sha1, :weak
```

これらのヘルパーは、キャッシングをしてくれませんが、必要な情報をキャッシュに与えてくれます。もし手早いリバースプロキシキャッシングの解決策をお探しなら、 [rack-cache](https://github.com/rtomayko/rack-cache)を試してください。


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

`:static_cache_control`設定(以下を参照)を、キャッシュ制御ヘッダ情報を静的ファイルに追加するために使ってください。

RFC 2616によれば、アプリケーションは、If-MatchまたはIf-None-Matchヘッダが`*`に設定されている場合には、要求されたリソースが既に存在するか否かに応じて、異なる振る舞いをすべきとなっています。Sinatraは、getのような安全なリクエストおよびputのような冪等なリクエストは既に存在しているものとして仮定し、一方で、他のリソース(例えば、postリクエスト)は新たなリソースとして取り扱われるよう仮定します。この振る舞いは、`:new_resource`オプションを渡すことで変更できます。

```ruby
get '/create' do
  etag '', :new_resource => true
  Article.create
  erb :new_article
end
```

ここでもWeak ETagを使いたい場合は、`:kind`オプションを渡してください。

```ruby
etag '', :new_resource => true, :kind => :weak
```

### ファイルの送信

ファイルを送信するには、`send_file`ヘルパーメソッドを使います。

```ruby
get '/' do
  send_file 'foo.png'
end
```

これはオプションを取ることもできます。

```ruby
send_file 'foo.png', :type => :jpg
```

オプション一覧

<dl>
  <dt>filename</dt>
    <dd>ファイル名。デフォルトは実際のファイル名。</dd>

  <dt>last_modified</dt>
    <dd>Last-Modifiedヘッダの値。デフォルトはファイルのmtime。</dd>

  <dt>type</dt>
    <dd>コンテンツの種類。設定がない場合、ファイル拡張子から類推される。</dd>

  <dt>disposition</dt>
    <dd>
      Content-Dispositionに使われる。許容値: <tt>nil</tt> (デフォルト)、
      <tt>:attachment</tt> および <tt>:inline</tt>
    </dd>

  <dt>length</dt>
    <dd>Content-Lengthヘッダ。デフォルトはファイルサイズ。</dd>

  <dt>status</dt>
    <dd>
      送られるステータスコード。静的ファイルをエラーページとして送るときに便利。

      Rackハンドラでサポートされている場合は、Rubyプロセスからのストリーミング以外の手段が使われる。このヘルパーメソッドを使うと、Sinatraは自動で範囲リクエスト(range requests)を扱う。
    </dd>
</dl>


### リクエストオブジェクトへのアクセス

受信するリクエストオブジェクトは、`request`メソッドを通じてリクエストレベル(フィルタ、ルーティング、エラーハンドラ)からアクセスすることができます。

```ruby
# アプリケーションが http://example.com/example で動作している場合
get '/foo' do
  t = %w[text/css text/html application/javascript]
  request.accept              # ['text/html', '*/*']
  request.accept? 'text/xml'  # true
  request.preferred_type(t)   # 'text/html'
  request.body                # クライアントによって送信されたリクエストボディ(下記参照)
  request.scheme              # "http"
  request.script_name         # "/example"
  request.path_info           # "/foo"
  request.port                # 80
  request.request_method      # "GET"
  request.query_string        # ""
  request.content_length      # request.bodyの長さ
  request.media_type          # request.bodyのメディアタイプ
  request.host                # "example.com"
  request.get?                # true (他の動詞にも同種メソッドあり)
  request.form_data?          # false
  request["some_param"]       # some_param変数の値。[]はパラメータハッシュのショートカット
  request.referrer            # クライアントのリファラまたは'/'
  request.user_agent          # ユーザエージェント (:agent 条件によって使用される)
  request.cookies             # ブラウザクッキーのハッシュ
  request.xhr?                # Ajaxリクエストかどうか
  request.url                 # "http://example.com/example/foo"
  request.path                # "/example/foo"
  request.ip                  # クライアントのIPアドレス
  request.secure?             # false (sslではtrueになる)
  request.forwarded?          # true (リバースプロキシの裏で動いている場合)
  request.env                 # Rackによって渡された生のenvハッシュ
end
```

`script_name`や`path_info`などのオプションは次のように利用することもできます。

```ruby
before { request.path_info = "/" }

get "/" do
  "全てのリクエストはここに来る"
end
```

`request.body`はIOまたはStringIOのオブジェクトです。

```ruby
post "/api" do
  request.body.rewind  # 既に読まれているときのため
  data = JSON.parse request.body.read
  "Hello #{data['name']}!"
end
```

### アタッチメント(Attachments)

`attachment`ヘルパーを使って、レスポンスがブラウザに表示されるのではなく、ディスクに保存されることをブラウザに対し通知することができます。

```ruby
get '/' do
  attachment
  "保存しました!"
end
```

ファイル名を渡すこともできます。

```ruby
get '/' do
  attachment "info.txt"
  "保存しました!"
end
```

### 日付と時刻の取り扱い

Sinatraは`time_for`ヘルパーメソッドを提供しており、それは与えられた値からTimeオブジェクトを生成します。これはまた`DateTime`、`Date`および類似のクラスを変換できます。

```ruby
get '/' do
  pass if Time.now > time_for('Dec 23, 2012')
  "まだ時間がある"
end
```

このメソッドは、`expires`、`last_modified`といった種類のものの内部で使われています。そのため、アプリケーションにおいて、`time_for`をオーバーライドすることでそれらのメソッドの挙動を簡単に拡張できます。

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

### テンプレートファイルの探索

`find_template`ヘルパーは、レンダリングのためのテンプレートファイルを見つけるために使われます。

```ruby
find_template settings.views, 'foo', Tilt[:haml] do |file|
  puts "could be #{file}"
end
```

この例はあまり有益ではありません。しかし、このメソッドを、独自の探索機構で働くようオーバーライドするなら有益になります。例えば、複数のビューディレクトリを使えるようにしたいときがあります。


```ruby
set :views, ['views', 'templates']

helpers do
  def find_template(views, name, engine, &block)
    Array(views).each { |v| super(v, name, engine, &block) }
  end
end
```

他の例としては、異なるエンジン用の異なるディレクトリを使う場合です。

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

これをエクステンションとして書いて、他の人と簡単に共有することもできます！

ノート: `find_template`はファイルが実際に存在するかのチェックをしませんが、与えられたブロックをすべての可能なパスに対し呼び出します。これがパフォーマンス上の問題にはならないのは、`render`はファイルを見つけると直ちに`break`を使うからです。また、テンプレートの場所（および内容）は、developmentモードでの起動でない限りはキャッシュされます。このことは、複雑なメソッド(a really crazy method)を書いた場合は記憶しておく必要があります。

## コンフィギュレーション(Configuration)

どの環境でも起動時に１回だけ実行されます。

```ruby
configure do
  # １つのオプションをセット
  set :option, 'value'

  # 複数のオプションをセット
  set :a => 1, :b => 2

  # `set :option, true`と同じ
  enable :option

  # `set :option, false`と同じ
  disable :option

  # ブロックを使って動的な設定をすることもできます。
  set(:css_dir) { File.join(views, 'css') }
end
```

環境設定(`RACK_ENV`環境変数)が`:production`に設定されている時だけ実行する方法:

```ruby
configure :production do
  ...
end
```

環境設定が`:production`か`:test`に設定されている時だけ実行する方法:

```ruby
configure :production, :test do
  ...
end
```

設定したオプションには`settings`からアクセスできます:

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

### 攻撃防御に対する設定

Sinatraは、[Rack::Protection](https://github.com/sinatra/rack-protection#readme)を使って、アプリケーションを多発する日和見的攻撃から守っています。この挙動は簡単に無効化できます(これはアプリケーションを大量の脆弱性攻撃に晒すことになります)。

```ruby
disable :protection
```

単一の防御層を外すためには、`protection`をオプションハッシュにセットします。

```ruby
set :protection, :except => :path_traversal
```
また配列を渡して、複数の防御を無効にすることもできます。

```ruby
set :protection, :except => [:path_traversal, :session_hijacking]
```

デフォルトでSinatraは、`:sessions`が有効になっている場合、セッションベースの防御だけを設定します。しかし、自身でセッションを設定したい場合があります。その場合は、`:session`オプションを渡すことにより、セッションベースの防御を設定することができます。

```ruby
use Rack::Session::Pool
set :protection, :session => true
```

### 利用可能な設定

<dl>
  <dt>absolute_redirects</dt>
  <dd>
    無効のとき、Sinatraは相対リダイレクトを許容するが、RFC 2616 (HTTP 1.1)は絶対リダイレクトのみを許容するので、これには準拠しなくなる。
  </dd>
  <dd>
    アプリケーションが、適切に設定されていないリバースプロキシの裏で走っている場合は有効。ノート: <tt>url</tt>ヘルパーは、第２引数に<tt>false</tt>を渡さない限り、依然として絶対URLを生成する。
  </dd>
  <dd>デフォルトは無効。</dd>

  <dt>add_charset</dt>
  <dd>
    Mimeタイプ <tt>content_type</tt>ヘルパーが自動的にキャラクタセット情報をここに追加する。このオプションは書き換えるのではなく、値を追加するようにすること。
    <tt>settings.add_charset << "application/foobar"</tt>
  </dd>

  <dt>app_file</dt>
  <dd>
    メインのアプリケーションファイルのパスであり、プロジェクトのルート、viewsおよびpublicフォルダを見つけるために使われる。
  </dd>

  <dt>bind</dt>
  <dd>バインドするIPアドレス(デフォルト: `environment`がdevelopmentにセットされているときは、<tt>0.0.0.0</tt> <em>または</em> <tt>localhost</tt>)。ビルトインサーバでのみ使われる。</dd>

  <dt>default_encoding</dt>
  <dd>不明なときに仮定されるエンコーディング(デフォルトは<tt>"utf-8"</tt>)。</dd>

  <dt>dump_errors</dt>
  <dd>ログにおけるエラーの表示。</dd>

  <dt>environment</dt>
  <dd>
    現在の環境。デフォルトは<tt>ENV['RACK_ENV']</tt>、それが無い場合は<tt>"development"</tt>。
  </dd>

  <dt>logging</dt>
  <dd>ロガーの使用。</dd>

  <dt>lock</dt>
  <dd>
    各リクエスト周りのロックの配置で、Rubyプロセスごとにリクエスト処理を並行して走らせるようにする。
  </dd>
  <dd>アプリケーションがスレッドセーフでなければ有効。デフォルトは無効。</dd>

  <dt>method_override</dt>
  <dd>
    put/deleteフォームを、それらをサポートしないブラウザで使えるように<tt>_method</tt>のおまじないを使えるようにする。
  </dd>

  <dt>port</dt>
  <dd>待ち受けポート。ビルトインサーバのみで有効。</dd>

  <dt>prefixed_redirects</dt>
  <dd>
    絶対パスが与えられていないときに、リダイレクトに<tt>request.script_name</tt>を挿入するか否かの設定。これにより<tt>redirect '/foo'</tt>は、<tt>redirect to('/foo')</tt>のように振る舞う。デフォルトは無効。
  </dd>

  <dt>protection</dt>
  <dd>Web攻撃防御を有効にするか否かの設定。上述の攻撃防御の項を参照。</dd>

  <dt>public_dir</dt>
  <dd><tt>public_folder</tt>のエイリアス。以下を参照。</dd>

  <dt>public_folder</dt>
  <dd>
    publicファイルが提供されるディレクトリのパス。静的ファイルの提供が有効になっている場合にのみ使われる (以下の<tt>static</tt>設定を参照)。設定されていない場合、<tt>app_file</tt>設定から推定。
  </dd>

  <dt>reload_templates</dt>
  <dd>
    リクエスト間でテンプレートを再ロードするか否かの設定。developmentモードでは有効。
  </dd>

  <dt>root</dt>
  <dd>
    プロジェクトのルートディレクトリのパス。設定されていない場合、<tt>app_file</tt>設定から推定。
  </dd>

  <dt>raise_errors</dt>
  <dd>
    例外発生の設定(アプリケーションは止まる)。<tt>environment</tt>が<tt>"test"</tt>に設定されているときはデフォルトは有効。それ以外は無効。
  </dd>

  <dt>run</dt>
  <dd>
    有効のとき、SinatraがWebサーバの起動を取り扱う。rackupまたは他の手段を使うときは有効にしないこと。
  </dd>

  <dt>running</dt>
  <dd>ビルトインサーバが稼働中か？この設定を変更しないこと！</dd>

  <dt>server</dt>
  <dd>
    ビルトインサーバとして使用するサーバまたはサーバ群の指定。指定順位は優先度を表し、デフォルトはRuby実装に依存。
  </dd>

  <dt>sessions</dt>
  <dd>
    <tt>Rack::Session::Cookie</tt>を使ったクッキーベースのセッションサポートの有効化。詳しくは、'セッションの使用'の項を参照のこと。
  </dd>

  <dt>show_exceptions</dt>
  <dd>
    例外発生時にブラウザにスタックトレースを表示する。<tt>environment</tt>が<tt>"development"</tt>に設定されているときは、デフォルトで有効。それ以外は無効。
  </dd>
  <dd>
    また、<tt>:after_handler</tt>をセットすることができ、これにより、ブラウザにスタックトレースを表示する前に、アプリケーション固有のエラーハンドリングを起動させられる。
  </dd>

  <dt>static</dt>
  <dd>Sinatraが静的ファイルの提供を取り扱うかの設定。</dd>
  <dd>その取り扱いができるサーバを使う場合は無効。</dd>
  <dd>無効化でパフォーマンスは改善する</dd>
  <dd>
    クラッシックスタイルではデフォルトで有効。モジュラースタイルでは無効。
  </dd>

  <dt>static_cache_control</dt>
  <dd>
    Sinatraが静的ファイルを提供するときこれをセットして、レスポンスに<tt>Cache-Control</tt>ヘッダを追加するようにする。<tt>cache_control</tt>ヘルパーを使うこと。デフォルトは無効。
  </dd>
  <dd>
    複数の値をセットするときは明示的に配列を使う:
    <tt>set :static_cache_control, [:public, :max_age => 300]</tt>
  </dd>

  <dt>threaded</dt>
  <dd>
    <tt>true</tt>に設定されているときは、Thinにリクエストを処理するために<tt>EventMachine.defer</tt>を使うことを通知する。
  </dd>

  <dt>views</dt>
  <dd>
    ビューディレクトリのパス。設定されていない場合、<tt>app_file</tt>設定から推定する。
  </dd>

  <dt>x_cascade</dt>
  <dd>
    マッチするルーティングが無い場合に、X-Cascadeヘッダをセットするか否かの設定。デフォルトは<tt>true</tt>。
  </dd>
</dl>

## 環境設定(Environments)

３種類の既定環境、`"development"`、`"production"`および`"test"`があります。環境は、`RACK_ENV`環境変数を通して設定できます。デフォルト値は、`"development"`です。`"development"`環境において、すべてのテンプレートは、各リクエスト間で再ロードされ、そして、特別の`not_found`および`error`ハンドラがブラウザにスタックトレースを表示します。`"production"`および`"test"`環境においては、テンプレートはデフォルトでキャッシュされます。

異なる環境を走らせるには、`RACK_ENV`環境変数を設定します。

```shell
RACK_ENV=production ruby my_app.rb
```

既定メソッド、`development?`、`test?`および`production?`を、現在の環境設定を確認するために使えます。

```ruby
get '/' do
  if settings.development?
    "development!"
  else
    "not development!"
  end
end
```

## エラーハンドリング(Error Handling)

エラーハンドラはルーティングおよびbeforeフィルタと同じコンテキストで実行されます。すなわちこれは、`haml`、`erb`、`halt`といった便利なものが全て使えることを意味します。

### 未検出(Not Found)

`Sinatra::NotFound`例外が発生したとき、またはレスポンスのステータスコードが404のときに、`not_found`ハンドラが発動します。

```ruby
not_found do
  'ファイルが存在しません'
end
```

### エラー(Error)

`error`ハンドラはルーティングブロックまたはフィルタ内で例外が発生したときはいつでも発動します。例外オブジェクトはRack変数`sinatra.error`から取得できます。

```ruby
error do
  'エラーが発生しました。 - ' + env['sinatra.error'].message
end
```

エラーをカスタマイズする場合は、

```ruby
error MyCustomError do
  'エラーメッセージ...' + env['sinatra.error'].message
end
```

と書いておいて、下記のように呼び出します。

```ruby
get '/' do
  raise MyCustomError, '何かがまずかったようです'
end
```

そうするとこうなります。

```
エラーメッセージ... 何かがまずかったようです
```

あるいは、ステータスコードに対応するエラーハンドラを設定することもできます。

```ruby
error 403 do
  'Access forbidden'
end

get '/secret' do
  403
end
```

範囲指定もできます。

```ruby
error 400..510 do
  'Boom'
end
```

Sinatraを開発環境の下で実行している場合は、特別な`not_found`および`error`ハンドラが導入され、これは親切なスタックトレースと追加のデバッギング情報をブラウザに表示します。


## Rackミドルウェア(Rack Middleware)

SinatraはRuby製Webフレームワークのミニマルな標準的インタフェースである[Rack](http://rack.github.io/)上に構築されています。アプリケーションデベロッパーにとってRackにおける最も興味深い機能は、「ミドルウェア(middleware)」をサポートしていることであり、これは、サーバとアプリケーションとの間に置かれ、HTTPリクエスト/レスポンスを監視および/または操作することで、各種の汎用的機能を提供するコンポーネントです。

Sinatraはトップレベルの`use`メソッドを通して、Rackミドルウェアパイプラインの構築を楽にします。

```ruby
require 'sinatra'
require 'my_custom_middleware'

use Rack::Lint
use MyCustomMiddleware

get '/hello' do
  'Hello World'
end
```

`use`の文法は、[Rack::Builder](http://www.rubydoc.info/github/rack/rack/master/Rack/Builder)DSLで定義されているそれ（rackupファイルで最もよく使われる）と同じです。例えば `use`メソッドは複数の引数、そしてブロックも取ることができます。

```ruby
use Rack::Auth::Basic do |username, password|
  username == 'admin' && password == 'secret'
end
```

Rackは、ロギング、デバッギング、URLルーティング、認証、セッション管理など、多様な標準的ミドルウェアを共に配布されています。Sinatraはその多くのコンポーネントを自動で使うよう基本設定されているため、通常、それらを`use`で明示的に指定する必要はありません。

便利なミドルウェアを以下で見つけられます。

[rack](https://github.com/rack/rack/tree/master/lib/rack)、
[rack-contrib](https://github.com/rack/rack-contrib#readm)、
または[Rack wiki](https://github.com/rack/rack/wiki/List-of-Middleware)。

## テスト(Testing)

SinatraでのテストはRackベースのテストライブラリまたはフレームワークを使って書くことができます。[Rack::Test](http://www.rubydoc.info/github/brynary/rack-test/master/frames)をお薦めします。

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
    assert_equal "Songbirdを使ってます!", last_response.body
  end
end
```

ノート: モジュラースタイルでSinatraを使う場合は、上記`Sinatra::Application`をアプリケーションのクラス名に置き換えてください。

## Sinatra::Base - ミドルウェア、ライブラリおよびモジュラーアプリ

軽量なアプリケーションであれば、トップレベルでアプリケーションを定義していくことはうまくいきますが、再利用性可能なコンポーネント、例えばRackミドルウェア、RailsのMetal、サーバコンポーネントを含むシンプルなライブラリ、あるいはSinatraの拡張プログラムを構築するような場合、これは無視できない欠点を持つものとなります。トップレベルは、軽量なアプリケーションのスタイルにおける設定（例えば、単一のアプリケーションファイル、`./public`および`./views`ディレクトリ、ロギング、例外詳細ページなど）を仮定しています。そこで`Sinatra::Base`の出番です。

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

`Sinatra::Base`のサブクラスで利用できるメソッドは、トップレベルDSLで利用できるものと全く同じです。ほとんどのトップレベルで記述されたアプリは、以下の２点を修正することで`Sinatra::Base`コンポーネントに変えることができます。

* `sinatra`の代わりに`sinatra/base`を読み込む
  (そうしない場合、SinatraのDSLメソッドの全てがmainの名前空間にインポートされます)
* ルーティング、エラーハンドラ、フィルタ、オプションを`Sinatra::Base`のサブクラスに書く

`Sinatra::Base`はまっさらです。ビルトインサーバを含む、ほとんどのオプションがデフォルトで無効になっています。利用可能なオプションとその挙動の詳細については[Configuring Settings](http://www.sinatrarb.com/configuration.html)(英語)をご覧下さい。

もしもクラシックスタイルと同じような挙動のアプリケーションをトップレベルで定義させる必要があれば、`Sinatra::Application`をサブクラス化させてください。

```ruby
require "sinatra/base"

class MyApp < Sinatra::Application
  get "/" do
    'Hello world!'
  end
end
```

### モジュラースタイル vs クラッシックスタイル

一般的認識と違って、クラッシックスタイルを使うことに問題はなにもありません。それがそのアプリケーションに合っているのであれば、モジュラーアプリケーションに移行する必要はありません。

モジュラースタイルを使わずにクラッシックスタイルを使った場合の一番の不利な点は、Rubyプロセスごとにただ一つのSinatraアプリケーションしか持てない点です。複数が必要な場合はモジュラースタイルに移行してください。モジュラースタイルとクラッシックスタイルを混合できないということはありません。

一方のスタイルから他方へ移行する場合、デフォルト設定がわずかに異なる点に注意が必要です。

<table>
  <tr>
    <th>設定</th>
    <th>クラッシック</th>
    <th>モジュラー</th>
    <th>モジュラー</th>
  </tr>

  <tr>
    <td>app_file</td>
    <td>sinatraを読み込むファイル</td>
    <td>Sinatra::Baseをサブクラス化したファイル</td>
    <td>Sinatra::Applicationをサブクラス化したファイル</td>
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

### モジュラーアプリケーションの提供

モジュラーアプリケーションを開始、つまり`run!`を使って開始させる二種類のやり方があります。

```ruby
# my_app.rb
require 'sinatra/base'

class MyApp < Sinatra::Base
  # ... アプリケーションのコードを書く ...

  # Rubyファイルが直接実行されたらサーバを立ち上げる
  run! if app_file == $0
end
```

として、次のように起動するか、

```shell
ruby my_app.rb
```

または、Rackハンドラを使えるようにする`config.ru`ファイルを書いて、

```ruby
# config.ru (rackupで起動)
require './my_app'
run MyApp
```

起動します。

```shell
rackup -p 4567
```

### config.ruを用いたクラッシックスタイルアプリケーションの使用

アプリケーションファイルと、

```ruby
# app.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

対応する`config.ru`を書きます。

```ruby
require './app'
run Sinatra::Application
```

### config.ruはいつ使うのか？

`config.ru`ファイルは、以下の場合に適しています。

* 異なるRackハンドラ(Passenger, Unicorn, Herokuなど)でデプロイしたいとき
* `Sinatra::Base`の複数のサブクラスを使いたいとき
* Sinatraをミドルウェアとして利用し、エンドポイントとしては利用しないとき

**モジュラースタイルに移行したという理由だけで、`config.ru`に移行する必要はなく、`config.ru`で起動するためにモジュラースタイルを使う必要はありません。**

### Sinatraのミドルウェアとしての利用

Sinatraは他のRackミドルウェアを利用することができるだけでなく、
全てのSinatraアプリケーションは、それ自体ミドルウェアとして別のRackエンドポイントの前に追加することが可能です。

このエンドポイントには、別のSinatraアプリケーションまたは他のRackベースのアプリケーション(Rails/Ramaze/Camping/…)が用いられるでしょう。

```ruby
require 'sinatra/base'

class LoginScreen < Sinatra::Base
  enable :sessions

  get('/login') { haml :login }

  post('/login') do
    if params['name'] = 'admin' and params['password'] = 'admin'
      session['user_name'] = params['name']
    else
      redirect '/login'
    end
  end
end

class MyApp < Sinatra::Base
  # ミドルウェアはbeforeフィルタの前に実行される
  use LoginScreen

  before do
    unless session['user_name']
      halt "アクセスは拒否されました。<a href='/login'>ログイン</a>してください。"
    end
  end

  get('/') { "Hello #{session['user_name']}." }
end
```

### 動的なアプリケーションの生成

新しいアプリケーションを実行時に、定数に割り当てることなく生成したくなる場合があるでしょう。`Sinatra.new`を使えばそれができます。

```ruby
require 'sinatra/base'
my_app = Sinatra.new { get('/') { "hi" } }
my_app.run!
```

これは省略できる引数として、それが継承するアプリケーションを取ります。

```ruby
# config.ru (rackupで起動)
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

これは特にSinatraのextensionをテストするときや、Sinatraを自身のライブラリで利用する場合に役立ちます。

これはまた、Sinatraをミドルウェアとして利用することを極めて簡単にします。

```ruby
require 'sinatra/base'

use Sinatra do
  get('/') { ... }
end

run RailsProject::Application
```

## スコープとバインディング(Scopes and Binding)

現在のスコープはどのメソッドや変数が利用可能かを決定します。

### アプリケーション/クラスのスコープ

全てのSinatraアプリケーションはSinatra::Baseのサブクラスに相当します。
もしトップレベルDSLを利用しているならば(`require 'sinatra'`)このクラスはSinatra::Applicationであり、
そうでなければ、あなたが明示的に作成したサブクラスです。
クラスレベルでは`get`や`before`のようなメソッドを持っています。
しかし`request`や`session`オブジェクトには、全てのリクエストに対する単一のアプリケーションクラスがあるだけなので、アクセスできません。

`set`によって作られたオプションはクラスレベルのメソッドです。

```ruby
class MyApp < Sinatra::Base
  # アプリケーションスコープの中だよ!
  set :foo, 42
  foo # => 42

  get '/foo' do
    # もうアプリケーションスコープの中にいないよ!
  end
end
```

次の場所ではアプリケーションスコープバインディングを持ちます。

* アプリケーションクラス本体
* 拡張によって定義されたメソッド
* `helpers`に渡されたブロック
* `set`の値として使われるProcまたはブロック
* `Sinatra.new`に渡されたブロック

このスコープオブジェクト(クラス)は次のように利用できます。

* configureブロックに渡されたオブジェクト経由(`configure { |c| ... }`)
* リクエストスコープの中での`settings`

### リクエスト/インスタンスのスコープ

やってくるリクエストごとに、あなたのアプリケーションクラスの新しいインスタンスが作成され、全てのハンドラブロックがそのスコープで実行されます。
このスコープの内側からは`request`や`session`オブジェクトにアクセスすることができ、`erb`や`haml`のようなレンダリングメソッドを呼び出すことができます。
リクエストスコープの内側からは、`settings`ヘルパーによってアプリケーションスコープにアクセスすることができます。

```ruby
class MyApp < Sinatra::Base
  # アプリケーションスコープの中だよ!
  get '/define_route/:name' do
    # '/define_route/:name'のためのリクエストスコープ
    @value = 42

    settings.get("/#{params['name']}") do
      # "/#{params['name']}"のためのリクエストスコープ
      @value # => nil (not the same request)
    end

    "ルーティングが定義された!"
  end
end
```

次の場所ではリクエストスコープバインディングを持ちます。

* get/head/post/put/delete/options/patch/link/unlink ブロック
* before/after フィルタ
* helper メソッド
* テンプレート/ビュー

### デリゲートスコープ

デリゲートスコープは、単にクラススコープにメソッドを転送します。
しかしながら、クラスのバインディングを持っていないため、クラススコープと全く同じふるまいをするわけではありません。
委譲すると明示的に示されたメソッドのみが利用可能であり、またクラススコープと変数/状態を共有することはできません(注:
異なった`self`を持っています)。
`Sinatra::Delegator.delegate :method_name`を呼び出すことによってデリゲートするメソッドを明示的に追加することができます。

次の場所ではデリゲートスコープを持ちます。

* もし`require "sinatra"`しているならば、トップレベルバインディング
* `Sinatra::Delegator` mixinでextendされたオブジェクト

コードをご覧ください: ここでは [Sinatra::Delegator
mixin](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/base.rb#L1609-1633)は[mainオブジェクトにextendされています](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/main.rb#L28-30)。

## コマンドライン

Sinatraアプリケーションは直接実行できます。

```shell
ruby myapp.rb [-h] [-x] [-e ENVIRONMENT] [-p PORT] [-o HOST] [-s HANDLER]
```

オプション:

```
-h # ヘルプ
-p # ポート指定(デフォルトは4567)
-o # ホスト指定(デフォルトは0.0.0.0)
-e # 環境を指定 (デフォルトはdevelopment)
-s # rackserver/handlerを指定 (デフォルトはthin)
-x # mutex lockを付ける (デフォルトはoff)
```

### マルチスレッド

_この[StackOverflow][so-answer]でのKonstantinによる回答を言い換えています。_

Sinatraでは同時実行モデルを負わせることはできませんが、根本的な部分であるThinやPuma、WebrickのようなRackハンドラ(サーバー)部分に委ねることができます。
Sinatra自身はスレッドセーフであり、もしRackハンドラが同時実行モデルのスレッドを使用していても問題はありません。
つまり、これはサーバーを起動させる時、特定のRackハンドラに対して正しい起動処理を特定することが出来ます。
この例はThinサーバーをマルチスレッドで起動する方法のデモです。

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

サーバーを開始するコマンドです。

```
thin --threaded start
```

[so-answer]: http://stackoverflow.com/questions/6278817/is-sinatra-multi-threaded/6282999#6282999)

## 必要環境

次のRubyバージョンが公式にサポートされています。

<dl>
  <dt>Ruby 1.8.7</dt>
  <dd>
    1.8.7は完全にサポートされていますが、特にそれでなければならないという理由がないのであれば、アップグレードまたはJRubyまたはRubiniusへの移行を薦めます。1.8.7のサポートがSinatra 2.0の前に終わることはないでしょう。Ruby 1.8.6はサポート対象外です。
  </dd>

  <dt>Ruby 1.9.2</dt>
  <dd>
    1.9.2は完全にサポートされています。1.9.2p0は、Sinatraを起動したときにセグメントフォルトを引き起こすことが分かっているので、使わないでください。公式なサポートは、少なくともSinatra 1.5のリリースまでは続きます。
  </dd>

  <dt>Ruby 1.9.3</dt>
  <dd>
    1.9.3は完全にサポート、そして推奨されています。以前のバージョンからの1.9.3への移行は全セッションを無効にする点、覚えておいてください。
  </dd>

  <dt>Ruby 2.0.0</dt>
  <dd>
    2.0.0は完全にサポート、そして推奨されています。現在、その公式サポートを終了する計画はありません。
  </dd>

  <dt>Rubinius</dt>
  <dd>
    Rubiniusは公式にサポートされています(Rubinius >= 2.x)。
    <tt>gem install puma</tt>することが推奨されています。
  </dd>

  <dt>JRuby</dt>
  <dd>
    JRubyの最新安定版が公式にサポートされています。JRubyでC拡張を使うことは推奨されていません。
    <tt>gem install trinidad</tt>することが推奨されています。
  </dd>
</dl>

開発チームは常に最新となるRubyバージョンに注視しています。

次のRuby実装は公式にはサポートされていませんが、Sinatraが起動すると報告されています。

* JRubyとRubiniusの古いバージョン
* Ruby Enterprise Edition
* MacRuby, Maglev, IronRuby
* Ruby 1.9.0と1.9.1 (これらの使用はお薦めしません)

公式サポートをしないという意味は、問題がそこだけで起こり、サポートされているプラットフォーム上では起きない場合に、開発チームはそれはこちら側の問題ではないとみなすということです。

開発チームはまた、ruby-head(最新となる2.1.0)に対しCIを実行していますが、それが一貫して動くようになるまで何も保証しません。2.1.0が完全にサポートされればその限りではありません。

Sinatraは、利用するRuby実装がサポートしているオペレーティングシステム上なら動作するはずです。

MacRubyを使う場合は、`gem install control_tower`してください。

Sinatraは現在、Cardinal、SmallRuby、BlueRubyまたは1.8.7以前のバージョンのRuby上では動作しません。

## 最新開発版

Sinatraの最新開発版のコードを使いたい場合は、マスターブランチに対してアプリケーションを走らせて構いません。ある程度安定しています。また、適宜プレリリース版gemをpushしているので、

```shell
gem install sinatra --pre
```

すれば、最新の機能のいくつかを利用できます。

### Bundlerを使う場合

最新のSinatraでアプリケーションを動作させたい場合には、[Bundler](http://bundler.io)を使うのがお薦めのやり方です。

まず、Bundlerがなければそれをインストールします。

```shell
gem install bundler
```

そして、プロジェクトのディレクトリで、`Gemfile`を作ります。

```ruby
source 'https://rubygems.org'
gem 'sinatra', :github => "sinatra/sinatra"

# 他の依存ライブラリ
gem 'haml'                    # Hamlを使う場合
gem 'activerecord', '~> 3.0'  # ActiveRecord 3.xが必要かもしれません
```

ノート: `Gemfile`にアプリケーションの依存ライブラリのすべてを並べる必要があります。しかし、Sinatraが直接依存するもの(RackおよびTile)はBundlerによって自動的に取り込まれ、追加されます。

これで、以下のようにしてアプリケーションを起動することができます。

```shell
bundle exec ruby myapp.rb
```

### 直接組み込む場合

ローカルにクローンを作って、`sinatra/lib`ディレクトリを`$LOAD_PATH`に追加してアプリケーションを起動します。

```shell
cd myapp
git clone git://github.com/sinatra/sinatra.git
ruby -I sinatra/lib myapp.rb
```

追ってSinatraのソースを更新する方法。

```shell
cd myapp/sinatra
git pull
```

### グローバル環境にインストールする場合

Sinatraのgemを自身でビルドすることもできます。

```shell
git clone git://github.com/sinatra/sinatra.git
cd sinatra
rake sinatra.gemspec
rake install
```

gemをルートとしてインストールする場合は、最後のステップはこうなります。

```shell
sudo rake install
```

## バージョニング(Versioning)

Sinatraは、[Semantic Versioning](http://semver.org/)におけるSemVerおよびSemVerTagの両方に準拠しています。

## 参考文献

* [プロジェクトサイト](http://www.sinatrarb.com/) - ドキュメント、ニュース、他のリソースへのリンクがあります。
* [プロジェクトに参加(貢献)する](http://www.sinatrarb.com/contributing.html) - バグレポート パッチの送信、サポートなど
* [Issue tracker](https://github.com/sinatra/sinatra/issues)
* [Twitter](https://twitter.com/sinatra)
* [メーリングリスト](http://groups.google.com/group/sinatrarb/topics)
* http://freenode.net上のIRC: [#sinatra](irc://chat.freenode.net/#sinatra)
* [Sinatra Book](https://github.com/sinatra/sinatra-book/) クックブック、チュートリアル
* [Sinatra Recipes](http://recipes.sinatrarb.com/) コミュニティによるレシピ集
* http://www.rubydoc.info/上のAPIドキュメント: [最新版(latest release)用](http://www.rubydoc.info/gems/sinatra)または[現在のHEAD用](http://www.rubydoc.info/github/sinatra/sinatra)
* [CIサーバ](https://travis-ci.org/sinatra/sinatra)
* [Greenbear Laboratory Rack日本語マニュアル](http://route477.net/w/RackReferenceJa.html)
