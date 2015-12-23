function createSourceLinks() {
    $('.method_details_list .source_code').
        before("<span class='showSource'>[<a href='#' class='toggleSource'>View source</a>]</span>");
    $('.toggleSource').toggle(function() {
       $(this).parent().nextAll('.source_code').slideDown(100);
       $(this).text("Hide source");
    },
    function() {
        $(this).parent().nextAll('.source_code').slideUp(100);
        $(this).text("View source");
    });
}

function createDefineLinks() {
    var tHeight = 0;
    $('.defines').after(" <a href='#' class='toggleDefines'>more...</a>");
    $('.toggleDefines').toggle(function() {
        tHeight = $(this).parent().prev().height();
        $(this).prev().show();
        $(this).parent().prev().height($(this).parent().height());
        $(this).text("(less)");
    },
    function() {
        $(this).prev().hide();
        $(this).parent().prev().height(tHeight);
        $(this).text("more...");
    });
}

function createFullTreeLinks() {
    var tHeight = 0;
    $('.inheritanceTree').toggle(function() {
        tHeight = $(this).parent().prev().height();
        $(this).parent().toggleClass('showAll');
        $(this).text("(hide)");
        $(this).parent().prev().height($(this).parent().height());
    },
    function() {
        $(this).parent().toggleClass('showAll');
        $(this).parent().prev().height(tHeight);
        $(this).text("show all");
    });
}

function fixBoxInfoHeights() {
    $('dl.box dd.r1, dl.box dd.r2').each(function() {
       $(this).prev().height($(this).height());
    });
}

function searchFrameLinks() {
  $('.full_list_link').click(function() {
    toggleSearchFrame(this, $(this).attr('href'));
    return false;
  });
}

function toggleSearchFrame(id, link) {
  var frame = $('#search_frame');
  $('#search a').removeClass('active').addClass('inactive');
  if (frame.attr('src') == link && frame.css('display') != "none") {
    frame.slideUp(100);
    $('#search a').removeClass('active inactive');
  }
  else {
    $(id).addClass('active').removeClass('inactive');
    frame.attr('src', link).slideDown(100);
  }
}

function linkSummaries() {
  $('.summary_signature').click(function() {
    document.location = $(this).find('a').attr('href');
  });
}

function framesInit() {
  if (hasFrames) {
    document.body.className = 'frames';
    $('#menu .noframes a').attr('href', document.location);
    try {
      window.top.document.title = $('html head title').text();
    } catch(error) {
      // some browsers will not allow this when serving from file://
      // but we don't want to stop the world.
    }
  }
  else {
    $('#menu .noframes a').text('frames').attr('href', framesUrl);
  }
}

function keyboardShortcuts() {
  if (window.top.frames.main) return;
  $(document).keypress(function(evt) {
    if (evt.altKey || evt.ctrlKey || evt.metaKey || evt.shiftKey) return;
    if (typeof evt.target !== "undefined" &&
        (evt.target.nodeName == "INPUT" ||
        evt.target.nodeName == "TEXTAREA")) return;
    switch (evt.charCode) {
      case 67: case 99:  $('#class_list_link').click(); break;  // 'c'
      case 77: case 109: $('#method_list_link').click(); break; // 'm'
      case 70: case 102: $('#file_list_link').click(); break;   // 'f'
      default: break;
    }
  });
}

function summaryToggle() {
  $('.summary_toggle').click(function() {
    if (localStorage) {
      localStorage.summaryCollapsed = $(this).text();
    }
    $('.summary_toggle').each(function() {
      $(this).text($(this).text() == "collapse" ? "expand" : "collapse");
      var next = $(this).parent().parent().nextAll('ul.summary').first();
      if (next.hasClass('compact')) {
        next.toggle();
        next.nextAll('ul.summary').first().toggle();
      }
      else if (next.hasClass('summary')) {
        var list = $('<ul class="summary compact" />');
        list.html(next.html());
        list.find('.summary_desc, .note').remove();
        list.find('a').each(function() {
          $(this).html($(this).find('strong').html());
          $(this).parent().html($(this)[0].outerHTML);
        });
        next.before(list);
        next.toggle();
      }
    });
    return false;
  });
  if (localStorage) {
    if (localStorage.summaryCollapsed == "collapse") {
      $('.summary_toggle').first().click();
    }
    else localStorage.summaryCollapsed = "expand";
  }
}

function fixOutsideWorldLinks() {
  $('a').each(function() {
    if (window.location.host != this.host) this.target = '_parent';
  });
}

function generateTOC() {
  if ($('#filecontents').length === 0) return;
  var _toc = $('<ol class="top"></ol>');
  var show = false;
  var toc = _toc;
  var counter = 0;
  var tags = ['h2', 'h3', 'h4', 'h5', 'h6'];
  var i;
  if ($('#filecontents h1').length > 1) tags.unshift('h1');
  for (i = 0; i < tags.length; i++) { tags[i] = '#filecontents ' + tags[i]; }
  var lastTag = parseInt(tags[0][1], 10);
  $(tags.join(', ')).each(function() {
    if ($(this).parents('.method_details .docstring').length != 0) return;
    if (this.id == "filecontents") return;
    show = true;
    var thisTag = parseInt(this.tagName[1], 10);
    if (this.id.length === 0) {
      var proposedId = $(this).attr('toc-id');
      if (typeof(proposedId) != "undefined") this.id = proposedId;
      else {
        var proposedId = $(this).text().replace(/[^a-z0-9-]/ig, '_');
        if ($('#' + proposedId).length > 0) { proposedId += counter; counter++; }
        this.id = proposedId;
      }
    }
    if (thisTag > lastTag) {
      for (i = 0; i < thisTag - lastTag; i++) {
        var tmp = $('<ol/>'); toc.append(tmp); toc = tmp;
      }
    }
    if (thisTag < lastTag) {
      for (i = 0; i < lastTag - thisTag; i++) toc = toc.parent();
    }
    var title = $(this).attr('toc-title');
    if (typeof(title) == "undefined") title = $(this).text();
    toc.append('<li><a href="#' + this.id + '">' + title + '</a></li>');
    lastTag = thisTag;
  });
  if (!show) return;
  html = '<div id="toc"><p class="title"><a class="hide_toc" href="#"><strong>Table of Contents</strong></a> <small>(<a href="#" class="float_toc">left</a>)</small></p></div>';
  $('#content').prepend(html);
  $('#toc').append(_toc);
  $('#toc .hide_toc').toggle(function() {
    $('#toc .top').slideUp('fast');
    $('#toc').toggleClass('hidden');
    $('#toc .title small').toggle();
  }, function() {
    $('#toc .top').slideDown('fast');
    $('#toc').toggleClass('hidden');
    $('#toc .title small').toggle();
  });
  $('#toc .float_toc').toggle(function() {
    $(this).text('float');
    $('#toc').toggleClass('nofloat');
  }, function() {
    $(this).text('left');
    $('#toc').toggleClass('nofloat');
  });
}

$(framesInit);
$(createSourceLinks);
$(createDefineLinks);
$(createFullTreeLinks);
$(fixBoxInfoHeights);
$(searchFrameLinks);
$(linkSummaries);
$(keyboardShortcuts);
$(summaryToggle);
$(fixOutsideWorldLinks);
$(generateTOC);
