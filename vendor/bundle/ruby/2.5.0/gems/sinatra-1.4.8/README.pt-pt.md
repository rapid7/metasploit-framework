# Sinatra

*Atenção: Este documento é apenas uma tradução da versão em inglês e
pode estar desatualizado.*

Sinatra é uma
[DSL](https://pt.wikipedia.org/wiki/Linguagem_de_domínio_específico) para
criar rapidamente aplicações web em Ruby com o mínimo de esforço:

```ruby
# minhaapp.rb
require 'rubygems'
require 'sinatra'
get '/' do
  'Olá Mundo!'
end
```

Instale a gem e execute com:

```shell
sudo gem install sinatra
ruby minhaapp.rb
```

Aceda em: [http://localhost:4567](http://localhost:4567)

## Rotas

No Sinatra, uma rota é um metodo HTTP associado a uma URL correspondente
padrão. Cada rota é associada a um bloco:

```ruby
get '/' do
  .. mostrar algo ..
end

post '/' do
  .. criar algo ..
end

put '/' do
  .. atualizar algo ..
end

delete '/' do
  .. apagar algo ..
end
```

Rotas são encontradas na ordem em que são definidas. A primeira rota que
é encontrada invoca o pedido.

Padrões de rota podem incluir parâmetros nomeados, acessíveis através da
hash `params`:

```ruby
get '/ola/:nome' do
  # corresponde a "GET /ola/foo" e "GET /ola/bar"
  # params['nome'] é 'foo' ou 'bar'
  "Olá #{params['nome']}!"
end
```

Pode também aceder a parâmetros nomeados através do bloco de parâmetros:

```ruby
get '/ola/:nome' do |n|
  "Olá #{n}!"
end
```

Padrões de rota podem também incluir parâmetros splat (asteriscos),
acessíveis através do array `params['splat']`.

```ruby
get '/diga/*/ao/*' do
  # corresponde a /diga/ola/ao/mundo
  params['splat'] # => ["ola", "mundo"]
end

get '/download/*.*' do
  # corresponde a /download/pasta/do/arquivo.xml
  params['splat'] # => ["pasta/do/arquivo", "xml"]
end
```

Rotas correspondem-se com expressões regulares:

```ruby
get /\A\/ola\/([\w]+)\z/ do
  "Olá, #{params['captures'].first}!"
end
```

Ou com um bloco de parâmetro:

```ruby
get %r{/ola/([\w]+)} do |c|
  "Olá, #{c}!"
end
```

Rotas podem incluir uma variedade de condições correspondentes, por
exemplo, o agente usuário:

```ruby
get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
  "Você está a utilizar a versão #{params['agent'][0]} do Songbird."
end

get '/foo' do
  # Corresponde a um navegador não Songbird
end
```

## Arquivos estáticos

Arquivos estáticos são disponibilizados a partir do directório
`./public`. Você pode especificar um local diferente através da opção
`:public_folder`

```ruby
set :public_folder, File.dirname(__FILE__) + '/estatico'
```

Note que o nome do directório público não é incluido no URL. Um arquivo
`./public/css/style.css` é disponibilizado como
`http://example.com/css/style.css`.

## Views / Templates

Templates presumem-se estar localizados sob o directório `./views`. Para
utilizar um directório de views diferente:

```ruby
set :views, File.dirname(__FILE__) + '/modelo'
```

Uma coisa importante a ser lembrada é que você sempre tem as referências
dos templates como símbolos, mesmo se eles estiverem num sub-directório
(nesse caso utilize `:'subdir/template'`). Métodos de renderização irão
processar qualquer string passada directamente para elas.

### Haml Templates

A gem/biblioteca haml é necessária para renderizar templates HAML:

```ruby
# É necessário requerir 'haml' na aplicação.
require 'haml'

get '/' do
  haml :index
end
```

Renderiza `./views/index.haml`.

[Opções
Haml](http://haml.info/docs/yardoc/file.REFERENCE.html#options)
podem ser definidas globalmente através das configurações do sinatra,
veja [Opções e
Configurações](http://www.sinatrarb.com/configuration.html), e substitua
em uma requisição individual.

```ruby
set :haml, {:format => :html5 } # o formato padrão do Haml é :xhtml

get '/' do
  haml :index, :haml_options => {:format => :html4 } # substituido
end
```

### Erb Templates

```ruby
# É necessário requerir 'erb' na aplicação.
require 'erb'

get '/' do
  erb :index
end
```

Renderiza `./views/index.erb`

### Erubis

A gem/biblioteca erubis é necessária para renderizar templates erubis:

```ruby
# É necessário requerir 'erubis' na aplicação.
require 'erubis'

get '/' do
  erubis :index
end
```

Renderiza `./views/index.erubis`

### Builder Templates

A gem/biblioteca builder é necessária para renderizar templates builder:

```ruby
# É necessário requerir 'builder' na aplicação.
require 'builder'

get '/' do
  content_type 'application/xml', :charset => 'utf-8'
  builder :index
end
```

Renderiza `./views/index.builder`.

### Sass Templates

A gem/biblioteca sass é necessária para renderizar templates sass:

```ruby
# É necessário requerir 'haml' ou 'sass' na aplicação.
require 'sass'

get '/stylesheet.css' do
  content_type 'text/css', :charset => 'utf-8'
  sass :stylesheet
end
```

Renderiza `./views/stylesheet.sass`.

[Opções
Sass](http://sass-lang.com/documentation/file.SASS_REFERENCE.html#options)
podem ser definidas globalmente através das configurações do sinatra,
veja [Opções e
Configurações](http://www.sinatrarb.com/configuration.html), e substitua
em uma requisição individual.

```ruby
set :sass, {:style => :compact } # o estilo padrão do Sass é :nested

get '/stylesheet.css' do
  content_type 'text/css', :charset => 'utf-8'
  sass :stylesheet, :style => :expanded # substituido
end
```

### Less Templates

A gem/biblioteca less é necessária para renderizar templates Less:

```ruby
# É necessário requerir 'less' na aplicação.
require 'less'

get '/stylesheet.css' do
  content_type 'text/css', :charset => 'utf-8'
  less :stylesheet
end
```

Renderiza `./views/stylesheet.less`.

### Templates Inline

```ruby
get '/' do
  haml '%div.title Olá Mundo'
end
```

Renderiza a string, em uma linha, no template.

### Acedendo a Variáveis nos Templates

Templates são avaliados dentro do mesmo contexto que os manipuladores de
rota. Variáveis de instância definidas em rotas manipuladas são
directamente acedidas por templates:

```ruby
get '/:id' do
  @foo = Foo.find(params['id'])
  haml '%h1= @foo.nome'
end
```

Ou, especifique um hash explícito para variáveis locais:

```ruby
get '/:id' do
  foo = Foo.find(params['id'])
  haml '%h1= foo.nome', :locals => { :foo => foo }
end
```

Isso é tipicamente utilizado quando renderizamos templates parciais
(partials) dentro de outros templates.

### Templates Inline

Templates podem ser definidos no final do arquivo fonte(.rb):

```ruby
require 'rubygems'
require 'sinatra'

get '/' do
  haml :index
end

__END__

@@ layout
%html
  = yield

@@ index
%div.title Olá Mundo!!!!!
```

NOTA: Templates inline definidos no arquivo fonte são automaticamente
carregados pelo sinatra. Digite \`enable :inline\_templates\` se tem
templates inline no outro arquivo fonte.

### Templates nomeados

Templates também podem ser definidos utilizando o método top-level
`template`:

```ruby
template :layout do
  "%html\n  =yield\n"
end

template :index do
  '%div.title Olá Mundo!'
end

get '/' do
  haml :index
end
```

Se existir um template com nome “layout”, ele será utilizado sempre que
um template for renderizado. Pode desactivar layouts usando
`:layout => false`.

```ruby
get '/' do
  haml :index, :layout => !request.xhr?
end
```

## Helpers

Use o método de alto nível `helpers` para definir métodos auxiliares
para utilizar em manipuladores de rotas e modelos:

```ruby
helpers do
  def bar(nome)
    "#{nome}bar"
  end
end

get '/:nome' do
  bar(params['nome'])
end
```

## Filtros

Filtros Before são avaliados antes de cada requisição dentro do contexto
da requisição e podem modificar a requisição e a reposta. Variáveis de
instância definidas nos filtros são acedidas através de rotas e
templates:

```ruby
before do
  @nota = 'Olá!'
  request.path_info = '/foo/bar/baz'
end

get '/foo/*' do
  @nota #=> 'Olá!'
  params['splat'] #=> 'bar/baz'
end
```

Filtros After são avaliados após cada requisição dentro do contexto da
requisição e também podem modificar o pedido e a resposta. Variáveis de
instância definidas nos filtros before e rotas são acedidas através dos
filtros after:

```ruby
after do
  puts response.status
end
```

Filtros opcionalmente têm um padrão, fazendo com que sejam avaliados
somente se o caminho do pedido coincidir com esse padrão:

```ruby
before '/protected/*' do
  autenticar!
end

after '/create/:slug' do |slug|
  session[:last_slug] = slug
end
```

## Halting

Para parar imediatamente uma requisição dentro de um filtro ou rota
utilize:

```ruby
halt
```

Pode também especificar o status ao parar…

```ruby
halt 410
```

Ou com um corpo de texto…

```ruby
halt 'isto será o corpo de texto'
```

Ou também…

```ruby
halt 401, 'vamos embora!'
```

Com cabeçalhos…

```ruby
halt 402, {'Content-Type' => 'text/plain'}, 'revanche'
```

## Passing

Dentro de uma rota, pode passar para a próxima rota correspondente
usando `pass`:

```ruby
get '/adivinhar/:quem' do
  pass unless params['quem'] == 'Frank'
  'Apanhaste-me!'
end

get '/adivinhar/*' do
  'Falhaste!'
end
```

O bloqueio da rota é imediatamente encerrado e o controle continua com a
próxima rota de parâmetro. Se o parâmetro da rota não for encontrado, um
404 é retornado.

## Configuração

Correndo uma vez, na inicialização, em qualquer ambiente:

```ruby
configure do
  ...
end
```

Correndo somente quando o ambiente (`RACK_ENV` environment variável) é
definido para `:production`:

```ruby
configure :production do
  ...
end
```

Correndo quando o ambiente é definido para `:production` ou `:test`:

```ruby
configure :production, :test do
  ...
end
```

## Lidar com Erros

Lida-se com erros no mesmo contexto das rotas e filtros before, o que
signifca que `haml`, `erb`, etc, estão disponíveis.

### Não Encontrado

Quando um `Sinatra::NotFound` exception é levantado, ou o código de
status da reposta é 404, o manipulador `not_found` é invocado:

```ruby
not_found do
  'Isto está longe de ser encontrado'
end
```

### Erro

O manipulador `error` é invocado sempre que uma exceção é lançada a
partir de um bloco de rota ou um filtro. O objecto da exceção pode ser
obtido a partir da variável Rack `sinatra.error`:

```ruby
error do
  'Peço desculpa, houve um erro desagradável - ' + env['sinatra.error'].message
end
```

Erros personalizados:

```ruby
error MeuErroPersonalizado do
  'O que aconteceu foi...' + env['sinatra.error'].message
end
```

Então, se isso acontecer:

```ruby
get '/' do
  raise MeuErroPersonalizado, 'alguma coisa desagradável'
end
```

O resultado será:

```
O que aconteceu foi...alguma coisa desagradável
```

Alternativamente, pode definir um manipulador de erro para um código de
status:

```ruby
error 403 do
  'Accesso negado'
end

get '/secreto' do
  403
end
```

Ou um range (alcance):

```ruby
error 400..510 do
  'Boom'
end
```

O Sinatra define os manipuladores especiais `not_found` e `error` quando
corre no ambiente de desenvolvimento.

## Mime Types

Quando utilizamos `send_file` ou arquivos estáticos pode ter mime types
Sinatra não entendidos. Use `mime_type` para os registar por extensão de
arquivos:

```ruby
mime_type :foo, 'text/foo'
```

Pode também utilizar isto com o helper `content_type`:

```ruby
content_type :foo
```

## Middleware Rack

O Sinatra corre no [Rack](http://rack.github.io/), uma interface
padrão mínima para frameworks web em Ruby. Uma das capacidades mais
interessantes do Rack, para desenvolver aplicações, é o suporte de
“middleware” – componentes que residem entre o servidor e a aplicação,
monitorizando e/ou manipulando o pedido/resposta (request/response) HTTP
para providenciar varios tipos de funcionalidades comuns.

O Sinatra torna a construção de pipelines do middleware Rack fácil a um
nível superior utilizando o método `use`:

```ruby
require 'sinatra'
require 'meu_middleware_personalizado'

use Rack::Lint
use MeuMiddlewarePersonalizado

get '/ola' do
  'Olá mundo'
end
```

A semântica de `use` é idêntica aquela definida para a DSL
[Rack::Builder](http://www.rubydoc.info/github/rack/rack/master/Rack/Builder)
(mais frequentemente utilizada para arquivos rackup). Por exemplo, o
método `use` aceita múltiplos argumentos/variáveis, bem como blocos:

```ruby
use Rack::Auth::Basic do |utilizador, senha|
  utilizador == 'admin' && senha == 'secreto'
end
```

O Rack é distribuido com uma variedade de middleware padrões para logs,
debugs, rotas de URL, autenticação, e manipuladores de sessão.Sinatra
utiliza muitos desses componentes automaticamente dependendo da
configuração, por isso, tipicamente nao é necessário utilizar `use`
explicitamente.

## Testando

Testes no Sinatra podem ser escritos utilizando qualquer biblioteca ou
framework de teste baseados no Rack.
[Rack::Test](http://gitrdoc.com/brynary/rack-test) é recomendado:

```ruby
require 'minha_aplicacao_sinatra'
require 'rack/test'

class MinhaAplicacaoTeste < Minitest::Test
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def meu_test_default
    get '/'
    assert_equal 'Ola Mundo!', last_response.body
  end

  def teste_com_parametros
    get '/atender', :name => 'Frank'
    assert_equal 'Olá Frank!', last_response.bodymeet
  end

  def test_com_ambiente_rack
    get '/', {}, 'HTTP_USER_AGENT' => 'Songbird'
    assert_equal "Você está utilizando o Songbird!", last_response.body
  end
end
```

NOTA: Os módulos de classe embutidos `Sinatra::Test` e
`Sinatra::TestHarness` são depreciados na versão 0.9.2.

## Sinatra::Base - Middleware, Bibliotecas e aplicativos modulares

Definir sua aplicação a um nível superior de trabalho funciona bem para
micro aplicativos, mas tem consideráveis incovenientes na construção de
componentes reutilizáveis como um middleware Rack, metal Rails,
bibliotecas simples como um componente de servidor, ou mesmo extensões
Sinatra. A DSL de nível superior polui o espaço do objeto e assume um
estilo de configuração de micro aplicativos (exemplo: um simples arquivo
de aplicação, directórios `./public` e `./views`, logs, página de detalhes
de excepção, etc.). É onde o Sinatra::Base entra em jogo:

```ruby
require 'sinatra/base'

class MinhaApp < Sinatra::Base
  set :sessions, true
  set :foo, 'bar'

  get '/' do
    'Olá mundo!'
  end
end
```

A classe MinhaApp é um componente Rack independente que pode utilizar
como um middleware Rack, uma aplicação Rack, ou metal Rails. Pode
utilizar ou executar esta classe com um arquivo rackup `config.ru`;
ou, controlar um componente de servidor fornecendo como biblioteca:

```ruby
MinhaApp.run! :host => 'localhost', :port => 9090
```

Os métodos disponíveis para subclasses `Sinatra::Base` são exatamente como
aqueles disponíveis via a DSL de nível superior. Aplicações de nível
mais alto podem ser convertidas para componentes `Sinatra::Base` com duas
modificações:

-   Seu arquivo deve requerer `sinatra/base` ao invés de `sinatra`;
    outra coisa, todos os métodos DSL do Sinatra são importados para o
    espaço principal.

-   Coloque as rotas da sua aplicação, manipuladores de erro, filtros e
    opções na subclasse de um `Sinatra::Base`.

`Sinatra::Base` é um quadro branco. Muitas opções são desactivadas por
padrão, incluindo o servidor embutido. Veja [Opções e
Configurações](http://www.sinatrarb.com/configuration.html) para
detalhes de opções disponíveis e seus comportamentos.

SIDEBAR: A DSL de alto nível do Sinatra é implementada utilizando um simples
sistema de delegação. A classe `Sinatra::Application` – uma subclasse especial
da `Sinatra::Base` – recebe todos os `:get`, `:put`, `:post`, `:delete`,
`:before`, `:error`, `:not_found`, `:configure`, e `:set` messages enviados
para o alto nível. Dê você mesmo uma vista de olhos ao código: aqui está o
[Sinatra::Delegator
mixin](http://github.com/sinatra/sinatra/blob/ceac46f0bc129a6e994a06100aa854f606fe5992/lib/sinatra/base.rb#L1128)
sendo [incluido dentro de um espaço
principal](http://github.com/sinatra/sinatra/blob/ceac46f0bc129a6e994a06100aa854f606fe5992/lib/sinatra/main.rb#L28)

## Linha de Comandos

As aplicações Sinatra podem ser executadas directamente:

```shell
ruby minhaapp.rb [-h] [-x] [-e AMBIENTE] [-p PORTA] [-o HOST] [-s SERVIDOR]
```

As opções são:

```
-h # ajuda
-p # define a porta (padrão é 4567)
-o # define o host (padrão é 0.0.0.0)
-e # define o ambiente (padrão é development)
-s # especifica o servidor/manipulador rack (padrão é thin)
-x # activa o bloqueio (padrão é desligado)
```

## A última versão

Se gostaria de utilizar o código da última versão do Sinatra, crie um
clone local e execute sua aplicação com o directório `sinatra/lib` no
`LOAD_PATH`:

```shell
cd minhaapp
git clone git://github.com/sinatra/sinatra.git
ruby -I sinatra/lib minhaapp.rb
```

Alternativamente, pode adicionar o directório do `sinatra/lib` no
`LOAD_PATH` do seu aplicativo:

```ruby
$LOAD_PATH.unshift File.dirname(__FILE__) + '/sinatra/lib'
require 'rubygems'
require 'sinatra'

get '/sobre' do
  "Estou correndo a versão" + Sinatra::VERSION
end
```

Para actualizar o código do Sinatra no futuro:

```shell
cd meuprojeto/sinatra
git pull
```

## Mais

-   [Website do Projeto](http://www.sinatrarb.com/) - Documentação
    adicional, novidades e links para outros recursos.

-   [Contribuir](http://www.sinatrarb.com/contributing) - Encontrou um
    bug? Precisa de ajuda? Tem um patch?

-   [Acompanhar Questões](https://github.com/sinatra/sinatra/issues)

-   [Twitter](https://twitter.com/sinatra)

-   [Lista de Email](http://groups.google.com/group/sinatrarb/topics)

-   [IRC: \#sinatra](irc://chat.freenode.net/#sinatra) em
    [freenode.net](http://freenode.net)
