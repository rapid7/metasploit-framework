// Handle opening/closing module overview list items
jtd.onReady(function(ready) {
    var moduleStructures = document.querySelectorAll('.module-structure');
    for (var i = 0; i < moduleStructures.length; i++) {
        jtd.addEvent(moduleStructures[i], 'click', function (e) {
            var originalTarget = e.target || e.srcElement || e.originalTarget;
            if (originalTarget.tagName !== 'A') { return; }

            var parentListItem = originalTarget.closest('li');
            if (parentListItem.className.indexOf('folder') === -1) { return; }

            var childList = parentListItem.querySelector('ul');
            if (childList) {
                childList.classList.toggle('open');
            }
            e.preventDefault();
        });
    }
});
