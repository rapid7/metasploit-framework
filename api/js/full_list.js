var inSearch = null;
var searchIndex = 0;
var searchCache = [];
var searchString = '';
var regexSearchString = '';
var caseSensitiveMatch = false;
var ignoreKeyCodeMin = 8;
var ignoreKeyCodeMax = 46;
var commandKey = 91;

RegExp.escape = function(text) {
    return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
}

function fullListSearch() {
  // generate cache
  searchCache = [];
  $('#full_list li').each(function() {
    var link = $(this).find('.object_link a');
    if (link.length === 0) return;
    var fullName = link.attr('title').split(' ')[0];
    searchCache.push({name:link.text(), fullName:fullName, node:$(this), link:link});
  });

  $('#search input').keyup(function(event) {
    if ((event.keyCode > ignoreKeyCodeMin && event.keyCode < ignoreKeyCodeMax)
         || event.keyCode == commandKey)
      return;
    searchString = this.value;
    caseSensitiveMatch = searchString.match(/[A-Z]/) != null;
    regexSearchString = RegExp.escape(searchString);
    if (caseSensitiveMatch) {
      regexSearchString += "|" +
        $.map(searchString.split(''), function(e) { return RegExp.escape(e); }).
        join('.+?');
    }
    if (searchString === "") {
      clearTimeout(inSearch);
      inSearch = null;
      $('ul .search_uncollapsed').removeClass('search_uncollapsed');
      $('#full_list, #content').removeClass('insearch');
      $('#full_list li').removeClass('found').each(function() {

        var link = $(this).find('.object_link a');
        if (link.length > 0) link.text(link.text());
      });
      if (clicked) {
        clicked.parents('ul').each(function() {
          $(this).removeClass('collapsed').prev().removeClass('collapsed');
        });
      }
      highlight();
    }
    else {
      if (inSearch) clearTimeout(inSearch);
      searchIndex = 0;
      lastRowClass = '';
      $('#full_list, #content').addClass('insearch');
      $('#noresults').text('');
      searchItem();
    }
  });

  $('#search input').focus();
  $('#full_list').after("<div id='noresults'></div>");
}

var lastRowClass = '';
function searchItem() {
  for (var i = 0; i < searchCache.length / 50; i++) {
    var item = searchCache[searchIndex];
    var searchName = (searchString.indexOf('::') != -1 ? item.fullName : item.name);
    var matchString = regexSearchString;
    var matchRegexp = new RegExp(matchString, caseSensitiveMatch ? "" : "i");
    if (searchName.match(matchRegexp) == null) {
      item.node.removeClass('found');
    }
    else {
      item.node.css('padding-left', '10px').addClass('found');
      item.node.parents().addClass('search_uncollapsed');
      item.node.removeClass(lastRowClass).addClass(lastRowClass == 'r1' ? 'r2' : 'r1');
      lastRowClass = item.node.hasClass('r1') ? 'r1' : 'r2';
      item.link.html(item.name.replace(matchRegexp, "<strong>$&</strong>"));
    }

    if (searchCache.length === searchIndex + 1) {
      searchDone();
      return;
    }
    else {
      searchIndex++;
    }
  }
  inSearch = setTimeout('searchItem()', 0);
}

function searchDone() {
  highlight(true);
  if ($('#full_list li:visible').size() === 0) {
    $('#noresults').text('No results were found.').hide().fadeIn();
  }
  else {
    $('#noresults').text('');
  }
  $('#content').removeClass('insearch');
  clearTimeout(inSearch);
  inSearch = null;
}

clicked = null;
function linkList() {
  $('#full_list li, #full_list li a:last').click(function(evt) {
    if ($(this).hasClass('toggle')) return true;
    if (this.tagName.toLowerCase() == "li") {
      if ($(this).find('.object_link a').length === 0) {
        $(this).children('a.toggle').click();
        return false;
      }
      var toggle = $(this).children('a.toggle');
      if (toggle.size() > 0 && evt.pageX < toggle.offset().left) {
        toggle.click();
        return false;
      }
    }
    if (clicked) clicked.removeClass('clicked');
    var win;
    try {
      win = window.top.frames.main ? window.top.frames.main : window.parent;
    } catch (e) { win = window.parent; }
    if (this.tagName.toLowerCase() == "a") {
      clicked = $(this).parents('li').addClass('clicked');
      win.location = this.href;
    }
    else {
      clicked = $(this).addClass('clicked');
      win.location = $(this).find('a:last').attr('href');
    }
    return false;
  });
}

function collapse() {
  if (!$('#full_list').hasClass('class')) return;
  $('#full_list.class a.toggle').click(function() {
    $(this).parent().toggleClass('collapsed').next().toggleClass('collapsed');
    highlight();
    return false;
  });
  $('#full_list.class ul').each(function() {
    $(this).addClass('collapsed').prev().addClass('collapsed');
  });
  $('#full_list.class').children().removeClass('collapsed');
  highlight();
}

function highlight(no_padding) {
  var n = 1;
  $('#full_list li:visible').each(function() {
    var next = n == 1 ? 2 : 1;
    $(this).removeClass("r" + next).addClass("r" + n);
    if (!no_padding && $('#full_list').hasClass('class')) {
      $(this).css('padding-left', (10 + $(this).parents('ul').size() * 15) + 'px');
    }
    n = next;
  });
}

function escapeShortcut() {
  $(document).keydown(function(evt) {
    if (evt.which == 27) {
      $('#search_frame', window.top.document).slideUp(100);
      $('#search a', window.top.document).removeClass('active inactive');
      $(window.top).focus();
    }
  });
}

$(escapeShortcut);
$(fullListSearch);
$(linkList);
$(collapse);
