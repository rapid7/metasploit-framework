# Sinatra

## Содержание

* [Sinatra](#sinatra)
    * [Маршруты](#Маршруты)
        * [Условия](#Условия)
        * [Возвращаемые значения](#Возвращаемые-значения)
        * [Собственные детекторы совпадений для маршрутов](#Собственные-детекторы-совпадений-для-маршрутов)
    * [Статические файлы](#Статические-файлы)
    * [Представления / Шаблоны](#Представления--Шаблоны)
        * [Буквальные шаблоны](#Буквальные-шаблоны)
        * [Доступные шаблонизаторы](#Доступные-шаблонизаторы)
            * [Haml шаблоны](#haml-шаблоны)
            * [Erb шаблоны](#erb-шаблоны)
            * [Builder шаблоны](#builder-шаблоны)
            * [Nokogiri шаблоны](#nokogiri-шаблоны)
            * [Sass шаблоны](#sass-шаблоны)
            * [SCSS шаблоны](#scss-шаблоны)
            * [Less шаблоны](#less-шаблоны)
            * [Liquid шаблоны](#liquid-шаблоны)
            * [Markdown шаблоны](#markdown-шаблоны)
            * [Textile шаблоны](#textile-шаблоны)
            * [RDoc шаблоны](#rdoc-шаблоны)
            * [AsciiDoc шаблоны](#asciidoc-шаблоны)
            * [Radius шаблоны](#radius-шаблоны)
            * [Markaby шаблоны](#markaby-шаблоны)
            * [RABL шаблоны](#rabl-шаблоны)
            * [Slim шаблоны](#slim-шаблоны)
            * [Creole шаблоны](#creole-шаблоны)
            * [MediaWiki шаблоны](#mediawiki-шаблоны)
            * [CoffeeScript шаблоны](#coffeescript-шаблоны)
            * [Stylus шаблоны](#stylus-шаблоны)
            * [Yajl шаблоны](#yajl-шаблоны)
            * [WLang шаблоны](#wlang-шаблоны)
        * [Доступ к переменным в шаблонах](#Доступ-к-переменным-в-шаблонах)
        * [Шаблоны с `yield` и вложенные раскладки (layout)](#Шаблоны-с-yield-и-вложенные-раскладки-layout)
        * [Включённые шаблоны](#Включённые-шаблоны)
        * [Именованные шаблоны](#Именованные-шаблоны)
        * [Привязка файловых расширений](#Привязка-файловых-расширений)
        * [Добавление собственного движка рендеринга](#Добавление-собственного-движка-рендеринга)
    * [Фильтры](#Фильтры)
    * [Методы-помощники](#Методы-помощники)
        * [Использование сессий](#Использование-сессий)
        * [Прерывание](#Прерывание)
        * [Передача](#Передача)
        * [Вызов другого маршрута](#Вызов-другого-маршрута)
        * [Задание тела, кода и заголовков ответа](#Задание-тела-кода-и-заголовков-ответа)
        * [Стриминг ответов](#Стриминг-ответов)
        * [Логирование](#Логирование)
        * [Mime-типы](#mime-типы)
        * [Генерирование URL](#Генерирование-url)
        * [Перенаправление (редирект)](#Перенаправление-редирект)
        * [Управление кэшированием](#Управление-кэшированием)
        * [Отправка файлов](#Отправка-файлов)
        * [Доступ к объекту запроса](#Доступ-к-объекту-запроса)
        * [Вложения](#Вложения)
        * [Работа со временем и датами](#Работа-со-временем-и-датами)
        * [Поиск шаблонов](#Поиск-шаблонов)
    * [Конфигурация](#Конфигурация)
        * [Настройка защиты от атак](#Настройка-защиты-от-атак)
        * [Доступные настройки](#Доступные-настройки)
    * [Режим, окружение](#Режим-окружение)
    * [Обработка ошибок](#Обработка-ошибок)
        * [Not Found](#not-found)
        * [Error](#error)
    * [Rack "прослойки"](#rack-прослойки)
    * [Тестирование](#Тестирование)
    * [Sinatra::Base — "прослойки", библиотеки и модульные приложения](#sinatrabase--прослойки-библиотеки-и-модульные-приложения)
        * [Модульные приложения против классических](#Модульные-приложения-против-классических)
        * [Запуск модульных приложений](#Запуск-модульных-приложений)
        * [Запуск классических приложений с config.ru](#Запуск-классических-приложений-с-configru)
        * [Когда использовать config.ru?](#Когда-использовать-configru)
        * [Использование Sinatra в качестве "прослойки"](#Использование-sinatra-в-качестве-прослойки)
        * [Создание приложений "на лету"](#Создание-приложений-на-лету)
    * [Области видимости и привязка](#Области-видимости-и-привязка)
        * [Область видимости приложения / класса](#Область-видимости-приложения--класса)
        * [Область видимости запроса / экземпляра](#Область-видимости-запроса--экземпляра)
        * [Область видимости делегирования](#Область-видимости-делегирования)
    * [Командная строка](#Командная-строка)
        * [Multi-threading](#multi-threading)
    * [Системные требования](#Системные-требования)
    * [На острие](#На-острие)
        * [С помощью Bundler](#С-помощью-bundler)
        * [Вручную](#Вручную)
        * [Установка глобально](#Установка-глобально)
    * [Версии](#Версии)
    * [Дальнейшее чтение](#Дальнейшее-чтение)

*Внимание: Этот документ является переводом английской версии и может быть
устаревшим*

Sinatra — это предметно-ориентированный каркас
([DSL](https://ru.wikipedia.org/wiki/Предметно-ориентированный_язык))
для быстрого создания функциональных веб-приложений на Ruby с минимумом усилий:

```ruby
# myapp.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

Установите gem:

```shell
gem install sinatra
```

и запустите приложение с помощью:

```shell
ruby myapp.rb
```

Оцените результат: [http://localhost:4567](http://localhost:4567)

Рекомендуется также установить Thin, сделать это можно командой: `gem install
thin`. Thin — это более производительный и функциональный сервер для
разработки приложений на Sinatra.

## Маршруты

В Sinatra маршрут — это пара: &lt;HTTP метод&gt; и &lt;шаблон URL&gt;. Каждый маршрут
связан с блоком кода:

```ruby
get '/' do
  # .. что-то показать ..
end

post '/' do
  # .. что-то создать ..
end

put '/' do
  # .. что-то заменить ..
end

patch '/' do
  # .. что-то изменить ..
end

delete '/' do
  # .. что-то удалить ..
end

options '/' do
  # .. что-то ответить ..
end

link '/' do
  .. что-то подключить ..
end

unlink '/' do
  .. что-то отключить ..
end
```

Маршруты сверяются с запросом в порядке очередности их записи в файле
приложения. Первый же совпавший с запросом маршрут и будет вызван.

Шаблоны маршрутов могут включать в себя именованные параметры, доступные в xэше
`params`:

```ruby
get '/hello/:name' do
  # соответствует "GET /hello/foo" и "GET /hello/bar",
  # где params['name'] 'foo' или 'bar'
  "Hello #{params['name']}!"
end
```

Также можно использовать именованные параметры в качестве переменных блока:

```ruby
get '/hello/:name' do |n|
  "Hello #{n}!"
end
```

Шаблоны маршрутов также могут включать в себя splat (или '*' маску,
обозначающую любой символ) параметры, доступные в массиве `params['splat']`:

```ruby
get '/say/*/to/*' do
  # соответствует /say/hello/to/world
  params['splat'] # => ["hello", "world"]
end

get '/download/*.*' do
  # соответствует /download/path/to/file.xml
  params['splat'] # => ["path/to/file", "xml"]
end
```

Или с параметрами блока:

```ruby
get '/download/*.*' do |path, ext|
  [path, ext] # => ["path/to/file", "xml"]
end
```

Регулярные выражения в качестве шаблонов маршрутов:

```ruby
get /\A\/hello\/([\w]+)\z/ do
  "Hello, #{params['captures'].first}!"
end
```

Или с параметром блока:

```ruby
# Находит "GET /meta/hello/world", "GET /hello/world/1234" и так далее
get %r{/hello/([\w]+)} do |c|
  "Hello, #{c}!"
end
```

Шаблоны маршрутов могут иметь необязательные параметры:

```ruby
get '/posts/:format?' do
  # соответствует "GET /posts/", "GET /posts/json", "GET /posts/xml" и т.д.
end
```

Кстати, если вы не отключите защиту от обратного пути в директориях (path
traversal, см. ниже), путь запроса может быть изменен до начала поиска
подходящего маршрута.

### Условия

Маршруты могут включать различные условия совпадений, например, клиентское
приложение (user agent):

```ruby
get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
  "You're using Songbird version #{params['agent'][0]}"
end

get '/foo' do
  # соответствует не-songbird браузерам
end
```

Другими доступными условиями являются `host_name` и `provides`:

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

Вы можете задать собственные условия:

```ruby
set(:probability) { |value| condition { rand <= value } }

get '/win_a_car', :probability => 0.1 do
  "You won!"
end

get '/win_a_car' do
  "Sorry, you lost."
end
```

Для условия, которое принимает несколько параметров, используйте звездочку:

```ruby
set(:auth) do |*roles|   # <- обратите внимание на звездочку
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

### Возвращаемые значения

Возвращаемое значение блока маршрута ограничивается телом ответа, которое
будет передано HTTP клиенту, или следующей "прослойкой" (middleware) в Rack
стеке. Чаще всего это строка, как в примерах выше. Но также приемлемы и
другие значения.

Вы можете вернуть любой объект, который будет либо корректным Rack ответом,
объектом Rack body, либо кодом состояния HTTP:

* массив с тремя переменными: `[код (Fixnum), заголовки (Hash), тело ответа
  (должно отвечать на #each)]`;
* массив с двумя переменными: `[код (Fixnum), тело ответа (должно отвечать
  на #each)]`;
* объект, отвечающий на `#each`, который передает только строковые типы
  данных в этот блок;
* Fixnum, представляющий код состояния HTTP.


Таким образом, легко можно реализовать, например, поточный пример:

```ruby
class Stream
  def each
    100.times { |i| yield "#{i}\n" }
  end
end

get('/') { Stream.new }
```

Вы также можете использовать метод `stream` (описываемый ниже), чтобы
уменьшить количество дублируемого кода и держать логику стриминга прямо в
маршруте.

### Собственные детекторы совпадений для маршрутов

Как показано выше, Sinatra поставляется со встроенной поддержкой строк и
регулярных выражений в качестве шаблонов URL. Но и это еще не все. Вы можете
легко определить свои собственные детекторы совпадений (matchers) для
маршрутов:

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

Заметьте, что предыдущий пример, возможно, чересчур усложнен, потому что он
может быть реализован так:

```ruby
get // do
  pass if request.path_info == "/index"
  # ...
end
```

Или с использованием негативного просмотра вперед:

```ruby
get %r{^(?!/index$)} do
  # ...
end
```

## Статические файлы

Статические файлы отдаются из `./public` директории. Вы можете указать другое
место, используя опцию `:public_folder`:

```ruby
set :public_folder, File.dirname(__FILE__) + '/static'
```

Учтите, что имя директории со статическими файлами не включено в URL.
Например, файл `./public/css/style.css` будет доступен как
`http://example.com/css/style.css`.

Используйте опцию `:static_cache_control` (см. ниже), чтобы добавить заголовок
`Cache-Control`.

## Представления / Шаблоны

Каждый шаблонизатор представлен своим собственным методом. Эти методы попросту
возвращают строку:

```ruby
get '/' do
  erb :index
end
```

Отобразит `views/index.erb`.

Вместо имени шаблона вы так же можете передавать непосредственно само
содержимое шаблона:

```ruby
get '/' do
  code = "<%= Time.now %>"
  erb code
end
```

Эти методы принимают второй аргумент, хеш с опциями:

```ruby
get '/' do
  erb :index, :layout => :post
end
```

Отобразит `views/index.erb`, вложенным в `views/post.erb` (по умолчанию:
`views/layout.erb`, если существует).

Любые опции, не понимаемые Sinatra, будут переданы в шаблонизатор:

```ruby
get '/' do
  haml :index, :format => :html5
end
```

Вы также можете задавать опции для шаблонизаторов в общем:

```ruby
set :haml, :format => :html5

get '/' do
  haml :index
end
```

Опции, переданные в метод, переопределяют опции, заданные с помощью `set`.

Доступные опции:

<dl>
  <dt>locals</dt>
  <dd>
    Список локальных переменных, передаваемых в документ.
    Например: <tt>erb "<%= foo %>", :locals => {:foo => "bar"}</tt>
  </dd>

  <dt>default_encoding</dt>
  <dd>
    Кодировка, которую следует использовать, если не удалось определить
    оригинальную. По умолчанию: <tt>settings.default_encoding</tt>.
  </dd>

  <dt>views</dt>
  <dd>
    Директория с шаблонами. По умолчанию: <tt>settings.views</tt>.
  </dd>

  <dt>layout</dt>
  <dd>
    Использовать или нет лэйаут (<tt>true</tt> или <tt>false</tt>). Если же значение Symbol,
    то указывает, какой шаблон использовать в качестве лэйаута. Например:
    <tt>erb :index, :layout => !request.xhr?</tt>
  </dd>

  <dt>content_type</dt>
  <dd>
    Content-Type отображенного шаблона. По умолчанию: задается шаблонизатором.
  </dd>

  <dt>scope</dt>
  <dd>
    Область видимости, в которой рендерятся шаблоны. По умолчанию: экземпляр
    приложения. Если вы измените эту опцию, то переменные экземпляра и
    методы-помощники станут недоступными в ваших шаблонах.
  </dd>

  <dt>layout_engine</dt>
  <dd>
    Шаблонизатор, который следует использовать для отображения лэйаута.
    Полезная опция для шаблонизаторов, в которых нет никакой поддержки
    лэйаутов. По умолчанию: тот же шаблонизатор, что используется и для самого
    шаблона. Пример: <tt>set :rdoc, :layout_engine => :erb</tt>
  </dd>
</dl>

По умолчанию считается, что шаблоны находятся в директории `./views`. Чтобы
использовать другую директорию с шаблонами:

```ruby
set :views, settings.root + '/templates'
```

Важное замечание: вы всегда должны ссылаться на шаблоны с помощью символов
(Symbol), даже когда они в поддиректории (в этом случае используйте
`:'subdir/template'`). Вы должны использовать символы, потому что иначе
шаблонизаторы попросту отображают любые строки, переданные им.

### Буквальные шаблоны

```ruby
get '/' do
  haml '%div.title Hello World'
end
```

Отобразит шаблон, переданный строкой.

### Доступные шаблонизаторы

Некоторые языки шаблонов имеют несколько реализаций. Чтобы указать, какую
реализацию использовать, вам следует просто подключить нужную библиотеку:

```ruby
require 'rdiscount' # или require 'bluecloth'
get('/') { markdown :index }
```

#### Haml шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://haml.info/" title="haml">haml</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.haml</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>haml :index, :format => :html5</tt></td>
  </tr>
</table>

#### Erb шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td>
      <a href="http://www.kuwata-lab.com/erubis/" title="erubis">erubis</a>
      или erb (включен в Ruby)
    </td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.erb</tt>, <tt>.rhtml</tt> or <tt>.erubis</tt> (только Erubis)</td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>erb :index</tt></td>
  </tr>
</table>

#### Builder шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td>
      <a href="https://github.com/jimweirich/builder" title="builder">builder</a>
    </td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.builder</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>builder { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

Блок также используется и для встроенных шаблонов (см. пример).

#### Nokogiri шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://www.nokogiri.org/" title="nokogiri">nokogiri</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.nokogiri</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>nokogiri { |xml| xml.em "hi" }</tt></td>
  </tr>
</table>

Блок также используется и для встроенных шаблонов (см. пример).

#### Sass шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.sass</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>sass :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

#### SCSS шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.scss</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>scss :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

#### Less шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://lesscss.org/" title="less">less</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.less</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>less :stylesheet</tt></td>
  </tr>
</table>

#### Liquid шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://liquidmarkup.org/" title="liquid">liquid</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.liquid</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>liquid :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

Так как в Liquid шаблонах невозможно вызывать методы из Ruby (кроме `yield`), то
вы почти всегда будете передавать в шаблон локальные переменные.

#### Markdown шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td>
      Любая из библиотек:
        <a href="https://github.com/davidfstr/rdiscount" title="RDiscount">RDiscount</a>,
        <a href="https://github.com/vmg/redcarpet" title="RedCarpet">RedCarpet</a>,
        <a href="http://deveiate.org/projects/BlueCloth" title="BlueCloth">BlueCloth</a>,
        <a href="http://kramdown.gettalong.org/" title="kramdown">kramdown</a>,
        <a href="https://github.com/bhollis/maruku" title="maruku">maruku</a>
    </td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.markdown</tt>, <tt>.mkd</tt> and <tt>.md</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>markdown :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

В Markdown невозможно вызывать методы или передавать локальные переменные.
Следовательно, вам, скорее всего, придется использовать этот шаблон совместно
с другим шаблонизатором:

```ruby
erb :overview, :locals => { :text => markdown(:introduction) }
```

Заметьте, что вы можете вызывать метод `markdown` из других шаблонов:

```ruby
%h1 Hello From Haml!
%p= markdown(:greetings)
```

Вы не можете вызывать Ruby из Markdown, соответственно, вы не можете
использовать лэйауты на Markdown. Тем не менее, есть возможность использовать
один шаблонизатор для отображения шаблона, а другой для лэйаута с помощью
опции `:layout_engine`.

#### Textile шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://redcloth.org/" title="RedCloth">RedCloth</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.textile</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>textile :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

В Textile невозможно вызывать методы или передавать локальные переменные.
Следовательно, вам, скорее всего, придется использовать этот шаблон совместно
с другим шаблонизатором:

```ruby
erb :overview, :locals => { :text => textile(:introduction) }
```

Заметьте, что вы можете вызывать метод `textile` из других шаблонов:

```ruby
%h1 Hello From Haml!
%p= textile(:greetings)
```

Вы не можете вызывать Ruby из Textile, соответственно, вы не можете
использовать лэйауты на Textile. Тем не менее, есть возможность использовать
один шаблонизатор для отображения шаблона, а другой для лэйаута с помощью
опции `:layout_engine`.

#### RDoc шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://rdoc.sourceforge.net/" title="RDoc">RDoc</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.rdoc</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>rdoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

В RDoc невозможно вызывать методы или передавать локальные переменные.
Следовательно, вам, скорее всего, придется использовать этот шаблон совместно
с другим шаблонизатором:

```ruby
erb :overview, :locals => { :text => rdoc(:introduction) }
```

Заметьте, что вы можете вызывать метод `rdoc` из других шаблонов:

```ruby
%h1 Hello From Haml!
%p= rdoc(:greetings)
```

Вы не можете вызывать Ruby из RDoc, соответственно, вы не можете использовать
лэйауты на RDoc. Тем не менее, есть возможность использовать один шаблонизатор
для отображения шаблона, а другой для лэйаута с помощью опции
`:layout_engine`.

#### AsciiDoc шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://asciidoctor.org/" title="Asciidoctor">Asciidoctor</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.asciidoc</tt>, <tt>.adoc</tt> и <tt>.ad</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>asciidoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

Так как в AsciiDoc шаблонах невозможно вызывать методы из Ruby напрямую, то вы
почти всегда будете передавать в шаблон локальные переменные.

#### Radius шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="https://github.com/jlong/radius" title="Radius">Radius</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.radius</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>radius :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

Так как в Radius шаблонах невозможно вызывать методы из Ruby напрямую, то вы
почти всегда будете передавать в шаблон локальные переменные.

#### Markaby шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://markaby.github.io/" title="Markaby">Markaby</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.mab</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>markaby { h1 "Welcome!" }</tt></td>
  </tr>
</table>

Блок также используется и для встроенных шаблонов (см. пример).

#### RABL шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="https://github.com/nesquena/rabl" title="Rabl">Rabl</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.rabl</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>rabl :index</tt></td>
  </tr>
</table>

#### Slim шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="http://slim-lang.com/" title="Slim Lang">Slim Lang</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.slim</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>slim :index</tt></td>
  </tr>
</table>

#### Creole шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="https://github.com/minad/creole" title="Creole">Creole</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.creole</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>creole :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

В Creole невозможно вызывать методы или передавать локальные переменные.
Следовательно, вам, скорее всего, придется использовать этот шаблон совместно
с другим шаблонизатором:

```ruby
erb :overview, :locals => { :text => creole(:introduction) }
```

Заметьте, что вы можете вызывать метод `creole` из других шаблонов:

```ruby
%h1 Hello From Haml!
%p= creole(:greetings)
```

Вы не можете вызывать Ruby из Creole, соответственно, вы не можете
использовать лэйауты на Creole. Тем не менее, есть возможность использовать
один шаблонизатор для отображения шаблона, а другой для лэйаута с помощью
опции `:layout_engine`.

#### MediaWiki шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="https://github.com/nricciar/wikicloth" title="WikiCloth">WikiCloth</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.mediawiki</tt> и <tt>.mw</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>mediawiki :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

В разметке MediaWiki невозможно вызывать методы или передавать локальные переменные.
Следовательно, вам, скорее всего, придется использовать этот шаблон совместно
с другим шаблонизатором:

```ruby
erb :overview, :locals => { :text => mediawiki(:introduction) }
```

Заметьте, что вы можете вызывать метод `mediawiki` из других шаблонов:

```ruby
%h1 Hello From Haml!
%p= mediawiki(:greetings)
```

Вы не можете вызывать Ruby из MediaWiki, соответственно, вы не можете
использовать лэйауты на MediaWiki. Тем не менее, есть возможность использовать
один шаблонизатор для отображения шаблона, а другой для лэйаута с помощью
опции `:layout_engine`.

#### CoffeeScript шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td>
      <a href="https://github.com/josh/ruby-coffee-script" title="Ruby CoffeeScript">
        CoffeeScript
      </a> и
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        способ запускать JavaScript
      </a>
    </td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.coffee</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>coffee :index</tt></td>
  </tr>
</table>

#### Stylus шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td>
      <a href="https://github.com/forgecrafted/ruby-stylus" title="Ruby Stylus">
        Stylus
      </a> и
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        способ запускать JavaScript
      </a>
    </td>
  </tr>
  <tr>
    <td>Расширение файла</td>
    <td><tt>.styl</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>stylus :index</tt></td>
  </tr>
</table>

Перед тем, как использовать шаблоны стилус, загрузите `stylus` и
`stylus/tilt`:

```ruby
require 'sinatra'
require 'stylus'
require 'stylus/tilt'

get '/' do
  stylus :example
end
```

#### Yajl шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="https://github.com/brianmario/yajl-ruby" title="yajl-ruby">yajl-ruby</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.yajl</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
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

Содержимое шаблона интерпретируется как код на Ruby, а результирующая
переменная json затем конвертируется с помощью `#to_json`.

```ruby
json = { :foo => 'bar' }
json[:baz] = key
```

Опции `:callback` и `:variable` используются для "декорирования" итогового
объекта.

```ruby
var resource = {"foo":"bar","baz":"qux"}; present(resource);
```

#### WLang шаблоны

<table>
  <tr>
    <td>Зависимости</td>
    <td><a href="https://github.com/blambeau/wlang/" title="wlang">wlang</a></td>
  </tr>
  <tr>
    <td>Расширения файлов</td>
    <td><tt>.wlang</tt></td>
  </tr>
  <tr>
    <td>Пример</td>
    <td><tt>wlang :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

Так как в WLang шаблонах невозможно вызывать методы из Ruby напрямую (за
исключением `yield`), то вы почти всегда будете передавать в шаблон локальные
переменные.

### Доступ к переменным в шаблонах

Шаблоны интерпретируются в том же контексте, что и обработчики маршрутов.
Переменные экземпляра, установленные в процессе обработки маршрутов, будут
доступны напрямую в шаблонах:

```ruby
get '/:id' do
  @foo = Foo.find(params['id'])
  haml '%h1= @foo.name'
end
```

Либо установите их через хеш локальных переменных:

```ruby
get '/:id' do
  foo = Foo.find(params['id'])
  haml '%h1= bar.name', :locals => { :bar => foo }
end
```

Это обычный подход, когда шаблоны рендерятся как части других шаблонов.

### Шаблоны с `yield` и вложенные раскладки (layout)

Раскладка (layout) обычно представляет собой шаблон, который исполняет
`yield`.
Такой шаблон может быть либо использован с помощью опции `:template`,
как описано выше, либо он может быть дополнен блоком:

```ruby
    erb :post, :layout => false do
      erb :index
    end
```

Эти инструкции в основном эквивалентны `erb :index, :layout => :post`.

Передача блоков интерпретирующим шаблоны методам наиболее полезна для
создания вложенных раскладок:

```ruby
    erb :main_layout, :layout => false do
      erb :admin_layout do
        erb :user
      end
    end
```

Это же самое может быть сделано короче:

```ruby
    erb :admin_layout, :layout => :main_layout do
      erb :user
    end
```

В настоящее время, следующие интерпретирующие шаблоны методы
принимают блок:
`erb`, `haml`, `liquid`, `slim `, `wlang`.
Общий метод заполнения шаблонов `render` также принимает блок.

### Включённые шаблоны

Шаблоны также могут быть определены в конце исходного файла:

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

Заметьте: включённые шаблоны, определенные в исходном файле, который подключил
Sinatra, будут загружены автоматически. Вызовите `enable :inline_templates`
напрямую, если используете включённые шаблоны в других файлах.

### Именованные шаблоны

Шаблоны также могут быть определены при помощи `template` метода:

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

Если шаблон с именем "layout" существует, то он будет использоваться каждый
раз при рендеринге. Вы можете отключать лэйаут в каждом конкретном случае с
помощью `:layout => false` или отключить его для всего приложения: `set :haml,
:layout => false`:

```ruby
get '/' do
  haml :index, :layout => !request.xhr?
end
```

### Привязка файловых расширений

Чтобы связать расширение файла с движком рендеринга, используйте
`Tilt.register`. Например, если вы хотите использовать расширение `tt` для
шаблонов Textile:

```ruby
Tilt.register :tt, Tilt[:textile]
```

### Добавление собственного движка рендеринга

Сначала зарегистрируйте свой движок в Tilt, а затем создайте метод, отвечающий
за рендеринг:

```ruby
Tilt.register :myat, MyAwesomeTemplateEngine

helpers do
  def myat(*args) render(:myat, *args) end
end

get '/' do
  myat :index
end
```

Отобразит `./views/index.myat`. Чтобы узнать больше о Tilt, смотрите
https://github.com/rtomayko/tilt

## Фильтры

`before`-фильтры выполняются перед каждым запросом в том же контексте, что и
маршруты, и могут изменять как запрос, так и ответ на него. Переменные
экземпляра, установленные в фильтрах, доступны в маршрутах и шаблонах:

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

`after`-фильтры выполняются после каждого запроса в том же контексте
и могут изменять как запрос, так и ответ на него. Переменные
экземпляра, установленные в `before`-фильтрах и маршрутах, будут доступны в
`after`-фильтрах:

```ruby
after do
  puts response.status
end
```

Заметьте: если вы используете метод `body`, а не просто возвращаете строку из
маршрута, то тело ответа не будет доступно в `after`-фильтрах, так как оно
будет сгенерировано позднее.

Фильтры могут использовать шаблоны URL и будут интерпретированы, только если
путь запроса совпадет с этим шаблоном:

```ruby
before '/protected/*' do
  authenticate!
end

after '/create/:slug' do |slug|
  session['last_slug'] = slug
end
```

Как и маршруты, фильтры могут использовать условия:

```ruby
before :agent => /Songbird/ do
  # ...
end

after '/blog/*', :host_name => 'example.com' do
  # ...
end
```

## Методы-помощники

Используйте метод `helpers`, чтобы определить методы-помощники, которые в
дальнейшем можно будет использовать в обработчиках маршрутов и шаблонах:

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

Также методы-помощники могут быть заданы в отдельных модулях:

```ruby
module FooUtils
  def foo(name) "#{name}foo" end
end

module BarUtils
  def bar(name) "#{name}bar" end
end

helpers FooUtils, BarUtils
```

Эффект равносилен включению модулей в класс приложения.

### Использование сессий

Сессия используется, чтобы сохранять состояние между запросами. Если эта опция
включена, то у вас будет один хеш сессии на одну пользовательскую сессию:

```ruby
enable :sessions

get '/' do
  "value = " << session['value'].inspect
end

get '/:value' do
  session['value'] = params['value']
end
```

Заметьте, что при использовании `enable :sessions` все данные сохраняются в
куках (cookies). Это может быть не совсем то, что вы хотите (например,
сохранение больших объемов данных увеличит ваш трафик). В таком случае вы
можете использовать альтернативную Rack "прослойку" (middleware), реализующую
механизм сессий. Для этого *не надо* вызывать `enable :sessions`, вместо этого
следует подключить ее так же, как и любую другую "прослойку":

```ruby
use Rack::Session::Pool, :expire_after => 2592000

get '/' do
  "value = " << session['value'].inspect
end

get '/:value' do
  session['value'] = params['value']
end
```

Для повышения безопасности данные сессии в куках подписываются секретным
ключом. Секретный ключ генерируется Sinatra. Тем не менее, так как этот ключ
будет меняться с каждым запуском приложения, вы, возможно, захотите установить
ключ вручную, чтобы у всех экземпляров вашего приложения был один и тот же
ключ:

```ruby
set :session_secret, 'super secret'
```

Если вы хотите больше настроек для сессий, вы можете задать их, передав хеш
опций в параметр `sessions`:

```ruby
set :sessions, :domain => 'foo.com'
```

Чтобы сделать сессию доступной другим приложениям, размещенным на поддоменах
foo.com, добавьте *.* перед доменом:

```ruby
set :sessions, :domain => '.foo.com'
```

### Прерывание

Чтобы незамедлительно прервать обработку запроса внутри фильтра или маршрута,
используйте:

```ruby
halt
```

Можно также указать статус при прерывании:

```ruby
halt 410
```

Тело:

```ruby
halt 'this will be the body'
```

И то, и другое:

```ruby
halt 401, 'go away!'
```

Можно указать заголовки:

```ruby
halt 402, {'Content-Type' => 'text/plain'}, 'revenge'
```

И, конечно, можно использовать шаблоны с `halt`:

```ruby
halt erb(:error)
```

### Передача

Маршрут может передать обработку запроса следующему совпадающему маршруту,
используя `pass`:

```ruby
get '/guess/:who' do
  pass unless params['who'] == 'Frank'
  'You got me!'
end

get '/guess/*' do
  'You missed!'
end
```

Блок маршрута сразу же прерывается, и контроль переходит к следующему
совпадающему маршруту. Если соответствующий маршрут не найден, то ответом на
запрос будет 404.

### Вызов другого маршрута

Иногда `pass` не подходит, например, если вы хотите получить результат вызова
другого обработчика маршрута. В таком случае просто используйте `call`:

```ruby
get '/foo' do
  status, headers, body = call env.merge("PATH_INFO" => '/bar')
  [status, headers, body.map(&:upcase)]
end

get '/bar' do
  "bar"
end
```

Заметьте, что в предыдущем примере можно облегчить тестирование и повысить
производительность, перенеся `"bar"` в метод-помощник, используемый и в
`/foo`, и в `/bar`.

Если вы хотите, чтобы запрос был отправлен в тот же экземпляр приложения, а не
в его копию, используйте `call!` вместо `call`.

Если хотите узнать больше о `call`, смотрите спецификацию Rack.

### Задание тела, кода и заголовков ответа

Хорошим тоном является установка кода состояния HTTP и тела ответа в
возвращаемом значении обработчика маршрута. Тем не менее, в некоторых
ситуациях вам, возможно, понадобится задать тело ответа в произвольной точке
потока исполнения. Вы можете сделать это с помощью метода-помощника `body`.
Если вы задействуете метод `body`, то вы можете использовать его и в
дальнейшем, чтобы получить доступ к телу ответа.

```ruby
get '/foo' do
  body "bar"
end

after do
  puts body
end
```

Также можно передать блок в метод `body`, который затем будет вызван
обработчиком Rack (такой подход может быть использован для реализации
поточного ответа, см. "Возвращаемые значения").

Аналогично вы можете установить код ответа и его заголовки:

```ruby
get '/foo' do
  status 418
  headers \
    "Allow"   => "BREW, POST, GET, PROPFIND, WHEN",
    "Refresh" => "Refresh: 20; http://www.ietf.org/rfc/rfc2324.txt"
  body "I'm a tea pot!"
end
```

Как и `body`, методы `headers` и `status`, вызванные без аргументов,
возвращают свои текущие значения.

### Стриминг ответов

Иногда требуется начать отправлять данные клиенту прямо в процессе
генерирования частей этих данных. В особых случаях требуется постоянно
отправлять данные до тех пор, пока клиент не закроет соединение. Вы можете
использовать метод `stream` вместо написания собственных "оберток".

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

Что позволяет вам реализовать стриминговые API,
[Server Sent Events](https://w3c.github.io/eventsource/),
и может служить основой для [WebSockets](https://en.wikipedia.org/wiki/WebSocket).
Также такой подход можно использовать для увеличения производительности в случае,
когда какая-то часть контента зависит от медленного ресурса.

Заметьте, что возможности стриминга, особенно количество одновременно
обслуживаемых запросов, очень сильно зависят от используемого веб-сервера.
Некоторые серверы могут и вовсе не поддерживать стриминг.  Если сервер не
поддерживает стриминг, то все данные будут отправлены за один раз сразу после
того, как блок, переданный в `stream`, завершится. Стриминг вообще не работает
при использовании Shotgun.

Если метод используется с параметром `keep_open`, то он не будет вызывать
`close` у объекта потока, что позволит вам закрыть его позже в любом другом
месте. Это работает только с событийными серверами, например, с Thin и
Rainbows. Другие же серверы все равно будут закрывать поток:

```ruby
# long polling

set :server, :thin
connections = []

get '/subscribe' do
  # регистрация клиента
  stream(:keep_open) do |out|
    connections << out }
    # удаление "мертвых клиентов"
    connections.reject!(&:closed?)
  end
end

post '/message' do
  connections.each do |out|
    # уведомить клиента о новом сообщении
    out << params['message'] << "\n"

    # указать клиенту на необходимость снова соединиться
    out.close
  end

  # допуск
  "message received"
end
```

### Логирование

В области видимости запроса метод `logger` предоставляет доступ к экземпляру
`Logger`:

```ruby
get '/' do
  logger.info "loading data"
  # ...
end
```

Этот логер автоматически учитывает ваши настройки логирования в Rack. Если
логирование выключено, то этот метод вернет пустой (dummy) объект, поэтому вы
можете смело использовать его в маршрутах и фильтрах.

Заметьте, что логирование включено по умолчанию только для
`Sinatra::Application`, а если ваше приложение — подкласс `Sinatra::Base`, то
вы, наверное, захотите включить его вручную:

```ruby
class MyApp < Sinatra::Base
  configure :production, :development do
    enable :logging
  end
end
```

Чтобы избежать использования любой логирующей "прослойки", задайте опции
`logging` значение `nil`. Тем не менее, не забывайте, что в такой ситуации
`logger` вернет `nil`. Чаще всего так делают, когда задают свой собственный
логер. Sinatra будет использовать то, что находится в `env['rack.logger']`.

### Mime-типы

Когда вы используете `send_file` или статические файлы, у вас могут быть
mime-типы, которые Sinatra не понимает по умолчанию. Используйте `mime_type`
для их регистрации по расширению файла:

```ruby
configure do
  mime_type :foo, 'text/foo'
end
```

Вы также можете использовать это в `content_type` методе-помощнике:

```ruby
get '/' do
  content_type :foo
  "foo foo foo"
end
```

### Генерирование URL

Чтобы сформировать URL, вам следует использовать метод `url`, например, в Haml:

```ruby
%a{:href => url('/foo')} foo
```

Этот метод учитывает обратные прокси и маршрутизаторы Rack, если они
присутствуют.

Наряду с `url` вы можете использовать `to` (смотрите пример ниже).

### Перенаправление (редирект)

Вы можете перенаправить браузер пользователя с помощью метода `redirect`:

```ruby
get '/foo' do
  redirect to('/bar')
end
```

Любые дополнительные параметры используются по аналогии с аргументами метода
`halt`:

```ruby
redirect to('/bar'), 303
redirect 'http://www.google.com/', 'wrong place, buddy'
```

Вы также можете перенаправить пользователя обратно, на страницу, с которой он
пришел, с помощью `redirect back`:

```ruby
get '/foo' do
  "<a href='/bar'>do something</a>"
end

get '/bar' do
  do_something
  redirect back
end
```

Чтобы передать какие-либо параметры вместе с перенаправлением, либо добавьте
их в строку запроса:

```ruby
redirect to('/bar?sum=42')
```

либо используйте сессию:

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

### Управление кэшированием

Установка корректных заголовков — основа правильного HTTP кэширования.

Вы можете легко выставить заголовок Cache-Control таким образом:

```ruby
get '/' do
  cache_control :public
  "cache it!"
end
```

Совет: задавайте кэширование в `before`-фильтре:

```ruby
before do
  cache_control :public, :must_revalidate, :max_age => 60
end
```

Если вы используете метод `expires` для задания соответствующего заголовка, то
`Cache-Control` будет выставлен автоматически:

```ruby
before do
  expires 500, :public, :must_revalidate
end
```

Чтобы как следует использовать кэширование, вам следует подумать об
использовании `etag` или `last_modified`. Рекомендуется использовать эти
методы-помощники *до* выполнения ресурсоемких вычислений, так как они
немедленно отправят ответ клиенту, если текущая версия уже есть в их кэше:

```ruby
get '/article/:id' do
  @article = Article.find params['id']
  last_modified @article.updated_at
  etag @article.sha1
  erb :article
end
```

Также вы можете использовать
[weak ETag](https://en.wikipedia.org/wiki/HTTP_ETag#Strong_and_weak_validation):

```ruby
etag @article.sha1, :weak
```

Эти методы-помощники не станут ничего кэшировать для вас, но они дадут
необходимую информацию для вашего кэша. Если вы ищете легкое решение для
кэширования, попробуйте [rack-cache](https://github.com/rtomayko/rack-cache):

```ruby
require 'rack/cache'
require 'sinatra'

use Rack::Cache

get '/' do
  cache_control :public, :max_age => 36000
  sleep 5
  "hello"
end
```

Используйте опцию `:static_cache_control` (см. ниже), чтобы добавить заголовок
`Cache-Control` к статическим файлам.

В соответствии с RFC 2616 ваше приложение должно вести себя по-разному, когда
заголовки If-Match или If-None-Match имеют значение `*`, в зависимости от
того, существует или нет запрашиваемый ресурс. Sinatra предполагает, что
ресурсы, к которым обращаются с помощью безопасных (GET) и идемпотентных (PUT)
методов, уже существуют, а остальные ресурсы (к которым обращаются, например,
с помощью POST) считает новыми. Вы можете изменить данное поведение с помощью
опции `:new_resource`:

```ruby
get '/create' do
  etag '', :new_resource => true
  Article.create
  erb :new_article
end
```

Если вы хотите использовать weak ETag, задайте опцию `:kind`:

```ruby
etag '', :new_resource => true, :kind => :weak
```

### Отправка файлов

Для отправки файлов пользователю вы можете использовать метод `send_file`:

```ruby
get '/' do
  send_file 'foo.png'
end
```

Этот метод имеет несколько опций:

```ruby
send_file 'foo.png', :type => :jpg
```

Возможные опции:

<dl>
  <dt>filename</dt>
  <dd>имя файла, по умолчанию: реальное имя файла.</dd>

  <dt>last_modified</dt>
  <dd>значение для заголовка Last-Modified, по умолчанию: mtime (время
      изменения) файла.</dd>

  <dt>type</dt>
  <dd>тип файла, по умолчанию: определяется по расширению файла.</dd>

  <dt>disposition</dt>
  <dd>используется для заголовка Content-Disposition, возможные значения: <tt>nil</tt>
      (по умолчанию), <tt>:attachment</tt> и <tt>:inline</tt>.</dd>

  <dt>length</dt>
  <dd>значения для заголовка Content-Length, по умолчанию: размер файла.</dd>

  <dt>status</dt>
  <dd>Код ответа. Полезно, когда отдается статический файл в качестве страницы с
      сообщением об ошибке.</dd>
</dl>

Этот метод будет использовать возможности Rack сервера для отправки файлов,
если они доступны, в противном случае будет напрямую отдавать файл из Ruby
процесса. Метод `send_file` также обеспечивает автоматическую обработку
частичных (range) запросов с помощью Sinatra.

### Доступ к объекту запроса

Объект входящего запроса доступен на уровне обработки запроса (в фильтрах,
маршрутах, обработчиках ошибок) с помощью `request` метода:

```ruby
# приложение запущено на http://example.com/example
get '/foo' do
  t = %w[text/css text/html application/javascript]
  request.accept              # ['text/html', '*/*']
  request.accept? 'text/xml'  # true
  request.preferred_type(t)   # 'text/html'
  request.body                # тело запроса, посланное клиентом (см. ниже)
  request.scheme              # "http"
  request.script_name         # "/example"
  request.path_info           # "/foo"
  request.port                # 80
  request.request_method      # "GET"
  request.query_string        # ""
  request.content_length      # длина тела запроса
  request.media_type          # медиатип тела запроса
  request.host                # "example.com"
  request.get?                # true (есть аналоги для других методов HTTP)
  request.form_data?          # false
  request["some_param"]       # значение параметра some_param. Шорткат для хеша params
  request.referrer            # источник запроса клиента либо '/'
  request.user_agent          # user agent (используется для :agent условия)
  request.cookies             # хеш, содержащий cookies браузера
  request.xhr?                # является ли запрос ajax запросом?
  request.url                 # "http://example.com/example/foo"
  request.path                # "/example/foo"
  request.ip                  # IP-адрес клиента
  request.secure?             # false (true, если запрос сделан через SSL)
  request.forwarded?          # true (если сервер работает за обратным прокси)
  request.env                 # "сырой" env хеш, полученный Rack
end
```

Некоторые опции, такие как `script_name` или `path_info`, доступны для
изменения:

```ruby
before { request.path_info = "/" }

get "/" do
  "all requests end up here"
end
```

`request.body` является IO или StringIO объектом:

```ruby
post "/api" do
  request.body.rewind  # в случае, если кто-то уже прочитал тело запроса
  data = JSON.parse request.body.read
  "Hello #{data['name']}!"
end
```

### Вложения

Вы можете использовать метод `attachment`, чтобы сказать браузеру, что ответ
сервера должен быть сохранен на диск, а не отображен:

```ruby
get '/' do
  attachment
  "store it!"
end
```

Вы также можете указать имя файла:

```ruby
get '/' do
  attachment "info.txt"
  "store it!"
end
```

### Работа со временем и датами

Sinatra предлагает метод-помощник `time_for`, который из заданного значения
создает объект Time. Он также может конвертировать `DateTime`, `Date` и
подобные классы:

```ruby
get '/' do
  pass if Time.now > time_for('Dec 23, 2012')
  "still time"
end
```

Этот метод используется внутри Sinatra методами `expires`, `last_modified` и
им подобными. Поэтому вы легко можете изменить и дополнить поведение этих методов,
переопределив `time_for` в своем приложении:

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

### Поиск шаблонов

Для поиска шаблонов и их последующего рендеринга используется метод
`find_template`:

```ruby
find_template settings.views, 'foo', Tilt[:haml] do |file|
  puts "could be #{file}"
end
```

Это не слишком полезный пример. Зато полезен тот факт, что вы можете
переопределить этот метод, чтобы использовать свой собственный механизм
поиска. Например, если вы хотите, чтобы можно было использовать несколько
директорий с шаблонами:

```ruby
set :views, ['views', 'templates']

helpers do
  def find_template(views, name, engine, &block)
    Array(views).each { |v| super(v, name, engine, &block) }
  end
end
```

Другой пример, в котором используются разные директории для движков
рендеринга:

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

Вы можете легко вынести этот код в расширение и поделиться им с остальными!

Заметьте, что `find_template` не проверяет, существует ли файл на самом деле,
а вызывает заданный блок для всех возможных путей. Дело тут не в
производительности, дело в том, что `render` вызовет `break`, как только файл
не будет найден. Содержимое и местонахождение шаблонов будет закэшировано,
если приложение запущено не в режиме разработки (`set :environment,
:development`). Вы должны помнить об этих нюансах,  если пишите по-настоящему
"сумасшедший" метод.

## Конфигурация

Этот блок исполняется один раз при старте в любом окружении, режиме
(environment):

```ruby
configure do
  # задание одной опции
  set :option, 'value'

  # устанавливаем несколько опций
  set :a => 1, :b => 2

  # то же самое, что и `set :option, true`
  enable :option

  # то же самое, что и `set :option, false`
  disable :option

  # у вас могут быть "динамические" опции с блоками
  set(:css_dir) { File.join(views, 'css') }
end
```

Будет запущено, когда окружение (RACK_ENV переменная) `:production`:

```ruby
configure :production do
  ...
end
```

Будет запущено, когда окружение `:production` или `:test`:

```ruby
configure :production, :test do
  ...
end
```

Вы можете получить доступ к этим опциям с помощью `settings`:

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

### Настройка защиты от атак

Sinatra использует
[Rack::Protection](https://github.com/sinatra/rack-protection#readme) для защиты
приложения от простых атак. Вы можете легко выключить эту защиту (что сделает
ваше приложение чрезвычайно уязвимым):

```ruby
disable :protection
```

Чтобы пропустить какой-либо уровень защиты, передайте хеш опций в параметр
`protection`:

```ruby
set :protection, :except => :path_traversal
```

Вы также можете отключить сразу несколько уровней защиты:

```ruby
set :protection, :except => [:path_traversal, :session_hijacking]
```

### Доступные настройки

<dl>
  <dt>absolute_redirects</dt>
  <dd>
    если отключено, то Sinatra будет позволять использование относительных
    перенаправлений, но при этом перестанет соответствовать RFC 2616 (HTTP
    1.1), который разрешает только абсолютные перенаправления.
  </dd>
  <dd>
    Включайте эту опцию, если ваше приложение работает за обратным прокси,
    который настроен не совсем корректно. Обратите внимание, метод <tt>url</tt> все
    равно будет генерировать абсолютные URL, если вы не передадите <tt>false</tt>
    вторым аргументом.
  </dd>
  <dd>Отключено по умолчанию.</dd>

  <dt>add_charset</dt>
  <dd>
    mime-типы, к которым метод <tt>content_type</tt> будет автоматически добавлять
    информацию о кодировке. Вам следует добавлять значения к этой опции
    вместо ее переопределения: <tt>settings.add_charset &lt;&lt; "application/foobar"</tt>
  </dd>

  <dt>app_file</dt>
  <dd>
    путь к главному файлу приложения, используется для нахождения корневой
    директории проекта, директорий с шаблонами и статическими файлами,
    вложенных шаблонов.
  </dd>

  <dt>bind</dt>
  <dd>
    используемый IP-адрес (по умолчанию: 0.0.0.0). Используется только
    встроенным сервером.
  </dd>

  <dt>default_encoding</dt>
  <dd>кодировка, если неизвестна (по умолчанию: <tt>"utf-8"</tt>).</dd>

  <dt>dump_errors</dt>
  <dd>отображать ошибки в логе.</dd>

  <dt>environment</dt>
  <dd>
    текущее окружение, по умолчанию, значение <tt>ENV['RACK_ENV']</tt> или
    <tt>"development"</tt>, если <tt>ENV['RACK_ENV']</tt> недоступна.
  </dd>

  <dt>logging</dt>
  <dd>использовать логер.</dd>

  <dt>lock</dt>
  <dd>
    создает блокировку для каждого запроса, которая гарантирует обработку
    только одного запроса в текущий момент времени в Ruby процессе.
  </dd>
  <dd>
    Включайте, если ваше приложение не потоко-безопасно (thread-safe).
    Отключено по умолчанию.</dd>

  <dt>method_override</dt>
  <dd>
    использовать "магический" параметр <tt>_method</tt>, для поддержки
    PUT/DELETE форм в браузерах, которые не поддерживают эти методы.
  </dd>

  <dt>port</dt>
  <dd>
    порт, на котором будет работать сервер.
    Используется только встроенным сервером.
  </dd>

  <dt>prefixed_redirects</dt>
  <dd>
    добавлять или нет параметр <tt>request.script_name</tt> к редиректам, если не
    задан абсолютный путь. Таким образом, <tt>redirect '/foo'</tt> будет вести себя
    как <tt>redirect to('/foo')</tt>. Отключено по умолчанию.
  </dd>

  <dt>protection</dt>
  <dd>включена или нет защита от атак. Смотрите секцию выше.</dd>

  <dt>public_dir</dt>
  <dd>Алиас для <tt>public_folder</tt>.</dd>

  <dt>public_folder</dt>
  <dd>
    путь к директории, откуда будут раздаваться статические файлы.
    Используется, только если включена раздача статических файлов
    (см. опцию <tt>static</tt> ниже).
  </dd>

  <dt>reload_templates</dt>
  <dd>
    перезагружать или нет шаблоны на каждый запрос. Включено в режиме
    разработки.
  </dd>

  <dt>root</dt>
  <dd>путь к корневой директории проекта.</dd>

  <dt>raise_errors</dt>
  <dd>
    выбрасывать исключения (будет останавливать приложение).
    По умолчанию включено только в окружении <tt>test</tt>.
  </dd>

  <dt>run</dt>
  <dd>
    если включено, Sinatra будет самостоятельно запускать веб-сервер. Не
    включайте, если используете rackup или аналогичные средства.
  </dd>

  <dt>running</dt>
  <dd>работает ли сейчас встроенный сервер? Не меняйте эту опцию!</dd>

  <dt>server</dt>
  <dd>
    сервер или список серверов, которые следует использовать в качестве
    встроенного сервера. По умолчанию: <tt>['thin', 'mongrel', 'webrick']</tt>, порядок
    задает приоритет.</dd>

  <dt>sessions</dt>
  <dd>
    включить сессии на основе кук (cookie) на базе <tt>Rack::Session::Cookie</tt>.
    Смотрите секцию "Использование сессий" выше.
  </dd>

  <dt>show_exceptions</dt>
  <dd>
    показывать исключения/стек вызовов (stack trace) в браузере. По умолчанию
    включено только в окружении <tt>development</tt>.
  </dd>
  <dd>
    Может быть установлено в
    <tt>:after_handler</tt> для запуска специфичной для приложения обработки ошибок,
    перед показом трассировки стека в браузере.
  </dd>

  <dt>static</dt>
  <dd>должна ли Sinatra осуществлять раздачу статических файлов.</dd>
  <dd>Отключите, когда используете какой-либо веб-сервер для этой цели.</dd>
  <dd>Отключение значительно улучшит производительность приложения.</dd>
  <dd>По умолчанию включено в классических и отключено в модульных приложениях.</dd>

  <dt>static_cache_control</dt>
  <dd>
    когда Sinatra отдает статические файлы, используйте эту опцию, чтобы
    добавить им заголовок <tt>Cache-Control</tt>. Для этого используется
    метод-помощник <tt>cache_control</tt>. По умолчанию отключено.
  </dd>
  <dd>
    Используйте массив, когда надо задать несколько значений:
    <tt>set :static_cache_control, [:public, :max_age => 300]</tt>
  </dd>

  <dt>threaded</dt>
  <dd>
    если включено, то Thin будет использовать <tt>EventMachine.defer</tt> для
    обработки запросов.
  </dd>

  <dt>traps</dt>
  <dd>должна ли Синатра обрабатывать системные сигналы или нет.</tt></dd>

  <dt>views</dt>
  <dd>путь к директории с шаблонами.</dd>
</dl>

## Режим, окружение

Есть 3 предопределенных режима, окружения: `"development"`, `"production"` и
`"test"`. Режим может быть задан через переменную окружения `RACK_ENV`.
Значение по умолчанию — `"development"`. В этом режиме работы все шаблоны
перезагружаются между запросами. А также задаются специальные обработчики
`not_found` и `error`, чтобы вы могли увидеть стек вызовов. В окружениях
`"production"` и `"test"` шаблоны по умолчанию кэшируются.

Для запуска приложения в определенном окружении используйте ключ `-e`

```
ruby my_app.rb -e [ENVIRONMENT]
```

Вы можете использовать предопределенные методы `development?`, `test?` и
+production?, чтобы определить текущее окружение.

## Обработка ошибок

Обработчики ошибок исполняются в том же контексте, что и маршруты, и
`before`-фильтры, а это означает, что всякие прелести вроде `haml`, `erb`,
`halt` и т.д. доступны и им.

### Not Found

Когда выброшено исключение `Sinatra::NotFound`, или кодом ответа является 404,
то будет вызван `not_found` обработчик:

```ruby
not_found do
  'This is nowhere to be found.'
end
```

### Error

Обработчик ошибок `error` будет вызван, когда исключение выброшено из блока
маршрута, либо из фильтра. Объект-исключение доступен как переменная
`sinatra.error` в Rack:

```ruby
error do
  'Sorry there was a nasty error - ' + env['sinatra.error'].message
end
```

Конкретные ошибки:

```ruby
error MyCustomError do
  'So what happened was...' + env['sinatra.error'].message
end
```

Тогда, если это произошло:

```ruby
get '/' do
  raise MyCustomError, 'something bad'
end
```

То вы получите:

```
So what happened was... something bad
```

Также вы можете установить обработчик ошибок для кода состояния HTTP:

```ruby
error 403 do
  'Access forbidden'
end

get '/secret' do
  403
end
```

Либо набора кодов:

```ruby
error 400..510 do
  'Boom'
end
```

Sinatra устанавливает специальные `not_found` и `error` обработчики, когда
приложение запущено в режиме разработки (окружение `:development`).

## Rack "прослойки"

Sinatra использует [Rack](http://rack.github.io/), минимальный стандартный
интерфейс для веб-фреймворков на Ruby. Одной из самых интересных для
разработчиков возможностей Rack является поддержка "прослоек" ("middleware") —
компонентов, находящихся "между" сервером и вашим приложением, которые
отслеживают и/или манипулируют HTTP запросами/ответами для предоставления
различной функциональности.

В Sinatra очень просто использовать такие "прослойки" с помощью метода `use`:

```ruby
require 'sinatra'
require 'my_custom_middleware'

use Rack::Lint
use MyCustomMiddleware

get '/hello' do
  'Hello World'
end
```

Семантика `use` идентична той, что определена для
[Rack::Builder](http://www.rubydoc.info/github/rack/rack/master/Rack/Builder) DSL
(чаще всего используется в rackup файлах). Например, метод `use` принимает как
множественные переменные, так и блоки:

```ruby
use Rack::Auth::Basic do |username, password|
  username == 'admin' && password == 'secret'
end
```

Rack распространяется с различными стандартными "прослойками" для логирования,
отладки, маршрутизации URL, аутентификации, обработки сессий. Sinatra
использует многие из этих компонентов автоматически, основываясь на
конфигурации, чтобы вам не приходилось подключать (`use`) их вручную.

Вы можете найти полезные прослойки в
[rack](https://github.com/rack/rack/tree/master/lib/rack),
[rack-contrib](https://github.com/rack/rack-contrib#readme),
или в
[Rack wiki](https://github.com/rack/rack/wiki/List-of-Middleware).

## Тестирование

Тесты для Sinatra приложений могут быть написаны с помощью библиотек,
фреймворков, поддерживающих тестирование Rack.
[Rack::Test](http://www.rubydoc.info/github/brynary/rack-test/master/frames)
рекомендован:

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

## Sinatra::Base — "прослойки", библиотеки и модульные приложения

Описание своего приложения самым простейшим способом (с помощью DSL верхнего
уровня, классический стиль) отлично работает для крохотных приложений. В таких
случаях используется конфигурация, рассчитанная на  микро-приложения
(единственный файл приложения, `./public` и `./views` директории, логирование,
страница информации об исключении и т.д.). Тем не менее, такой метод имеет
множество недостатков при создании компонентов, таких как Rack middleware
("прослоек"), Rails metal, простых библиотек с серверными компонентами,
расширений Sinatra. И тут на помощь приходит `Sinatra::Base`:

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

Методы, доступные `Sinatra::Base` подклассам идентичны тем, что доступны
приложениям в DSL верхнего уровня. Большинство таких приложений могут быть
конвертированы в `Sinatra::Base` компоненты с помощью двух модификаций:

* Вы должны подключать `sinatra/base` вместо `sinatra`, иначе все методы,
  предоставляемые Sinatra, будут импортированы в глобальное пространство
  имен.
* Поместите все маршруты, обработчики ошибок, фильтры и опции в подкласс
  `Sinatra::Base`.

`Sinatra::Base` — это чистый лист. Большинство опций, включая встроенный
сервер, по умолчанию отключены. Смотрите
[Опции и конфигурация](http://www.sinatrarb.com/configuration.html)
для детальной информации об опциях и их поведении.

### Модульные приложения против классических

Вопреки всеобщему убеждению, в классическом стиле (самом простом) нет ничего
плохого. Если этот стиль подходит вашему приложению, вы не обязаны
переписывать его в модульное приложение.

Основным недостатком классического стиля является тот факт, что у вас может
быть только одно приложение Sinatra на один процесс Ruby. Если вы планируете
использовать больше, переключайтесь на модульный стиль. Вы можете смело
смешивать модульный и классический стили.

Переходя с одного стиля на другой, примите во внимание следующие изменения в
настройках:

    Опция               Классический            Модульный

    app_file            файл с приложением      файл с подклассом Sinatra::Base
    run                 $0 == app_file          false
    logging             true                    false
    method_override     true                    false
    inline_templates    true                    false
    static              true                    File.exist?(public_folder)

### Запуск модульных приложений

Есть два общепринятых способа запускать модульные приложения: запуск напрямую
с помощью `run!`:

```ruby
# my_app.rb
require 'sinatra/base'

class MyApp < Sinatra::Base
  # ... здесь код приложения ...

  # запускаем сервер, если исполняется текущий файл
  run! if app_file == $0
end
```

Затем:

```
ruby my_app.rb
```

Или с помощью конфигурационного файла `config.ru`, который позволяет
использовать любой Rack-совместимый сервер приложений.

```ruby
# config.ru
require './my_app'
run MyApp
```

Запускаем:

```
rackup -p 4567
```

### Запуск классических приложений с config.ru

Файл приложения:

```ruby
# app.rb
require 'sinatra'

get '/' do
  'Hello world!'
end
```

И соответствующий `config.ru`:

```ruby
require './app'
run Sinatra::Application
```

### Когда использовать config.ru?

Вот несколько причин, по которым вы, возможно, захотите использовать
`config.ru`:

* вы хотите разворачивать свое приложение на различных Rack-совместимых
  серверах (Passenger, Unicorn, Heroku, ...);
* вы хотите использовать более одного подкласса `Sinatra::Base`;
* вы хотите использовать Sinatra только в качестве "прослойки" Rack.

**Совсем необязательно переходить на использование `config.ru` лишь потому,
что вы стали использовать модульный стиль приложения. И необязательно
использовать модульный стиль, чтобы запускать приложение с помощью
`config.ru`.**

### Использование Sinatra в качестве "прослойки"

Не только сама Sinatra может использовать "прослойки" Rack, но и любое Sinatra
приложение само может быть добавлено к любому Rack endpoint в качестве
"прослойки". Этим endpoint (конечной точкой) может быть другое Sinatra
приложение, или приложение, основанное на Rack (Rails/Ramaze/Camping/...):

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
  # "прослойка" будет запущена перед фильтрами
  use LoginScreen

  before do
    unless session['user_name']
      halt "Access denied, please <a href='/login'>login</a>."
    end
  end

  get('/') { "Hello #{session['user_name']}." }
end
```

### Создание приложений "на лету"

Иногда требуется создавать Sinatra приложения "на лету" (например, из другого
приложения). Это возможно с помощью `Sinatra.new`:

```ruby
require 'sinatra/base'
my_app = Sinatra.new { get('/') { "hi" } }
my_app.run!
```

Этот метод может принимать аргументом приложение, от которого следует
наследоваться:

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

Это особенно полезно для тестирования расширений Sinatra и при использовании
Sinatra внутри вашей библиотеки.

Благодаря этому, использовать Sinatra как "прослойку" очень просто:

```ruby
require 'sinatra/base'

use Sinatra do
  get('/') { ... }
end

run RailsProject::Application
```

## Области видимости и привязка

Текущая область видимости определяет методы и переменные, доступные в данный
момент.

### Область видимости приложения / класса

Любое Sinatra приложение соответствует подклассу `Sinatra::Base`. Если вы
используете DSL верхнего уровня (`require 'sinatra'`), то этим классом будет
`Sinatra::Application`, иначе это будет подкласс, который вы создали вручную.
На уровне класса вам будут доступны такие методы, как `get` или `before`, но
вы не сможете получить доступ к объектам `request` или `session`, так как
существует только один класс приложения для всех запросов.

Опции, созданные с помощью `set`, являются методами уровня класса:

```ruby
class MyApp < Sinatra::Base
  # Я в области видимости приложения!
  set :foo, 42
  foo # => 42

  get '/foo' do
    # Я больше не в области видимости приложения!
  end
end
```

У вас будет область видимости приложения внутри:

* тела вашего класса приложения;
* методов, определенных расширениями;
* блока, переданного в `helpers`;
* блоков, использованных как значения для `set`;
* блока, переданного в `Sinatra.new`.

Вы можете получить доступ к объекту области видимости (классу приложения)
следующими способами:

* через объект, переданный блокам конфигурации (`configure { |c| ... }`);
* `settings` внутри области видимости запроса.

### Область видимости запроса / экземпляра

Для каждого входящего запроса будет создан новый экземпляр вашего приложения,
и все блоки обработчика будут запущены в этом контексте. В этой области
видимости вам доступны `request` и `session` объекты, вызовы методов
рендеринга, такие как `erb` или `haml`. Вы можете получить доступ к области
видимости приложения из контекста запроса, используя метод-помощник
`settings`:

```ruby
class MyApp < Sinatra::Base
  # Я в области видимости приложения!
  get '/define_route/:name' do
    # Область видимости запроса '/define_route/:name'
    @value = 42

    settings.get("/#{params['name']}") do
      # Область видимости запроса "/#{params['name']}"
      @value # => nil (другой запрос)
    end

    "Route defined!"
  end
end
```

У вас будет область видимости запроса в:

* get/head/post/put/delete/options блоках;
* before/after фильтрах;
* методах-помощниках;
* шаблонах/отображениях.

### Область видимости делегирования

Область видимости делегирования просто перенаправляет методы в область
видимости класса. Однако, она не полностью ведет себя как область видимости
класса, так как у вас нет привязки к классу. Только методы, явно помеченные
для делегирования, будут доступны, а переменных/состояний области видимости
класса не будет (иначе говоря, у вас будет другой `self` объект). Вы можете
непосредственно добавить методы делегирования, используя
`Sinatra::Delegator.delegate :method_name`.

У вас будет контекст делегирования внутри:

*  привязки верхнего уровня, если вы сделали `require 'sinatra'`;
*  объекта, расширенного с помощью `Sinatra::Delegator`.

Посмотрите сами в код: вот
[примесь Sinatra::Delegator](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/base.rb#L1609-1633)
[расширяет главный объект](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/main.rb#L28-30).

## Командная строка

Sinatra приложения могут быть запущены напрямую:

```
ruby myapp.rb [-h] [-x] [-e ENVIRONMENT] [-p PORT] [-o HOST] [-s HANDLER]
```

Опции включают:

```
-h # раздел помощи
-p # указание порта (по умолчанию 4567)
-o # указание хоста (по умолчанию 0.0.0.0)
-e # указание окружения, режима (по умолчанию development)
-s # указание rack сервера/обработчика (по умолчанию thin)
-x # включить мьютекс-блокировку (по умолчанию выключена)
```

### Multi-threading

_Данный раздел является перефразированным [ответом пользователя Konstantin][so-answer] на StackOverflow_

Sinatra не навязывает каких-либо моделей параллелизма, но для этих целей можно
использовать любой Rack обработчик, например Thin, Puma или WEBrick. Сама
по себе Sinatra потокобезопасна, поэтому нет никаких проблем в использовании
поточной модели параллелизма в Rack обработчике. Это означает, что когда
запускается сервер, вы должны указать правильный метод вызова для конкретного
Rack обработчика. Пример ниже показывает, как можно запустить мультитредовый
Thin сервер:

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

Чтобы запустить сервер, вы должны выполнить следующую команду:

```shell
thin --threaded start
```

[so-answer]: http://stackoverflow.com/questions/6278817/is-sinatra-multi-threaded/6282999#6282999)

## Системные требования

Следующие версии Ruby официально поддерживаются:

<dl>
  <dt>Ruby 1.8.7</dt>
  <dd>1.8.7 полностью поддерживается, тем не менее, если вас ничто не держит на
    этой версии, рекомендуем обновиться до 1.9.2 или перейти на JRuby или
    Rubinius. Поддержка 1.8.7 не будет прекращена до выхода Sinatra 2.0 и Ruby
    2.0, разве что в случае релиза 1.8.8 (что маловероятно). Но даже тогда,
    возможно, поддержка не будет прекращена. <b>Ruby 1.8.6 больше не
    поддерживается.</b> Если вы хотите использовать 1.8.6, откатитесь до Sinatra
    1.2, которая будет получать все исправления ошибок до тех пор, пока не
    будет выпущена Sinatra 1.4.0.</dd>

  <dt>Ruby 1.9.2</dt>
  <dd>1.9.2 полностью поддерживается и рекомендована к использованию.
    Не используйте 1.9.2p0,
    известно, что эта версия очень нестабильна при использовании Sinatra. Эта
    версия будет поддерживаться по крайней мере до выхода Ruby 1.9.4/2.0, а
    поддержка последней версии 1.9 будет осуществляться до тех пор, пока она
    поддерживается командой разработчиков Ruby.</dd>

  <dt>Ruby 1.9.3</dt>
  <dd>1.9.3 полностью поддерживается. Заметьте, что переход на 1.9.3 с
    ранних версий сделает недействительными все сессии.</dd>

  <dt>Rubinius</dt>
  <dd>Rubinius официально поддерживается (Rubinius &gt;= 1.2.4), всё, включая все
  языки шаблонов, работает. Предстоящий релиз 2.0 также поддерживается.</dd>

  <dt>JRuby</dt>
  <dd>JRuby официально поддерживается (JRuby &gt;= 1.6.5). Нет никаких проблем с
  использованием альтернативных шаблонов. Тем не менее, если вы выбираете
  JRuby, то, пожалуйста, посмотрите на JRuby Rack-серверы, так как Thin не
  поддерживается полностью на JRuby. Поддержка расширений на C в JRuby все
  еще экспериментальная, что на данный момент затрагивает только RDiscount,
  Redcarpet и RedCloth.</dd>
</dl>

Мы также следим за предстоящими к выходу версиями Ruby.

Следующие реализации Ruby не поддерживаются официально, но известно, что на
них запускается Sinatra:

* старые версии JRuby и Rubinius;
* Ruby Enterprise Edition;
* MacRuby, Maglev, IronRuby;
* Ruby 1.9.0 и 1.9.1 (настоятельно не рекомендуются к использованию).

То, что версия официально не поддерживается, означает, что, если что-то не
работает на этой версии, а на поддерживаемой работает — это не наша проблема,
а их.

Мы также запускаем наши CI-тесты на версии Ruby, находящейся в разработке
(предстоящей 2.0.0), и на 1.9.4, но мы не можем ничего гарантировать, так как
они находятся в разработке. Предполагается, что 1.9.4p0 и 2.0.0p0 будут
поддерживаться.

Sinatra должна работать на любой операционной системе, в которой есть одна из
указанных выше версий Ruby.

Пока невозможно запустить Sinatra на Cardinal, SmallRuby, BlueRuby и на любой
версии Ruby до 1.8.7.

## На острие

Если вы хотите использовать самый последний код Sinatra, не бойтесь запускать
свое приложение вместе с кодом из master ветки Sinatra, она весьма стабильна.

Мы также время от времени выпускаем предварительные версии, так что вы можете
делать так:

```
gem install sinatra --pre
```

Чтобы воспользоваться некоторыми самыми последними возможностями.

### С помощью Bundler

Если вы хотите запускать свое приложение с последней версией Sinatra, то
рекомендуем использовать [Bundler](http://bundler.io).

Сначала установите Bundler, если у вас его еще нет:

```
gem install bundler
```

Затем создайте файл `Gemfile` в директории вашего проекта:

```ruby
source :rubygems
gem 'sinatra', :git => "git://github.com/sinatra/sinatra.git"

# другие зависимости
gem 'haml'                    # например, если используете haml
gem 'activerecord', '~> 3.0'  # может быть, вам нужен и ActiveRecord 3.x
```

Обратите внимание, вам нужно будет указывать все зависимости вашего приложения
в этом файле. Однако, непосредственные зависимости Sinatra (Rack и Tilt)
Bundler автоматически скачает и добавит.

Теперь вы можете запускать свое приложение так:

```
bundle exec ruby myapp.rb
```

### Вручную

Создайте локальный клон репозитория и запускайте свое приложение с
`sinatra/lib` директорией в `$LOAD_PATH`:

```
cd myapp
git clone git://github.com/sinatra/sinatra.git
ruby -Isinatra/lib myapp.rb
```

Чтобы обновить исходники Sinatra:

```
cd myapp/sinatra
git pull
```

### Установка глобально

Вы можете самостоятельно собрать gem:

```
git clone git://github.com/sinatra/sinatra.git
cd sinatra
rake sinatra.gemspec
rake install
```

Если вы устанавливаете пакеты (gem) от пользователя root, то вашим последним
шагом должна быть команда

```
sudo rake install
```

## Версии

Sinatra использует [Semantic Versioning](http://semver.org/), SemVer и
SemVerTag.

## Дальнейшее чтение

* [Веб-сайт проекта](http://www.sinatrarb.com/) — Дополнительная
  документация, новости и ссылки на другие ресурсы.
* [Участие в проекте](http://www.sinatrarb.com/contributing) — Обнаружили
  баг? Нужна помощь? Написали патч?
* [Отслеживание проблем/ошибок](https://github.com/sinatra/sinatra/issues)
* [Twitter](https://twitter.com/sinatra)
* [Группы рассылки](http://groups.google.com/group/sinatrarb/topics)
* IRC: [#sinatra](irc://chat.freenode.net/#sinatra) на http://freenode.net
* [Sinatra и Друзья](https://sinatrarb.slack.com) на Slack, а так же
  [ссылка](https://sinatra-slack.herokuapp.com/) для инвайта.
* [Sinatra Book](https://github.com/sinatra/sinatra-book/) учебник и сборник рецептов
* [Sinatra Recipes](http://recipes.sinatrarb.com/) сборник рецептов
* API документация к [последнему релизу](http://www.rubydoc.info/gems/sinatra)
  или [текущему HEAD](http://www.rubydoc.info/github/sinatra/sinatra) на
  http://www.rubydoc.info/
* [Сервер непрерывной интеграции](https://travis-ci.org/sinatra/sinatra)
