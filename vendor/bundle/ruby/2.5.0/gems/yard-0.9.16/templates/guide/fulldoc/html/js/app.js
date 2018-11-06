function generateTOC() {
  if ($('#filecontents').length == 0) return;
  var _toc = $('<ol class="top"></ol>');
  var show = false;
  var toc = _toc;
  var counter = 0;
  var tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
  for (i in tags) { tags[i] = '#filecontents > ' + tags[i] }
  var lastTag = parseInt(tags[0][1]);
  $(tags.join(', ')).each(function() {
    if (this.id == "filecontents") return;
    show = true;
    var thisTag = parseInt(this.tagName[1]);
    if (this.id.length == 0) {
      var proposedId = $(this).text().replace(/[^a-z0-9-]/ig, '_');
      if ($('#' + proposedId).length > 0) proposedId += counter++;
      this.id = proposedId;
    }
    if (thisTag > lastTag) {
      for (var i = 0; i < thisTag - lastTag; i++) {
        var tmp = $('<ol/>'); toc.append(tmp); toc = tmp;
      }
    }
    if (thisTag < lastTag) {
      for (var i = 0; i < lastTag - thisTag; i++) toc = toc.parent();
    }
    toc.append('<li><a href="#' + this.id + '">' + $(this).text() + '</a></li>');
    lastTag = thisTag;
  });
  if (!show) return;
  $('#toc').append()
  $('#toc').append(_toc);
}
