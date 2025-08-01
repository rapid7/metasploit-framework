// Handle opening/closing module overview list items
jtd.onReady(function(ready) {
    var forEach = function (list, callback) {
        for (var i = 0; i < list.length; i++) {
            callback(list[i])
        }
    };

    // Bind listeners for expand all / collapse all functionality
    var bindToggleAll = function (selector, options) {
        var isOpen = options.open;
        var expandAllButtons = document.querySelectorAll(selector);
        forEach(expandAllButtons, function (button) {
            jtd.addEvent(button, 'click', function (e) {
                var originalTarget = e.target || e.srcElement || e.originalTarget;
                if (originalTarget.tagName !== 'A') { return; }

                var moduleList = originalTarget.closest('.module-list');
                forEach(moduleList.querySelectorAll('.folder > ul'), function (list) {
                    if (isOpen) {
                        list.classList.add('open');
                    } else {
                        list.classList.remove('open');
                    }
                })

                e.preventDefault();
            });
        });
    };
    bindToggleAll('.module-list [data-expand-all]', { open: true })
    bindToggleAll('.module-list [data-collapse-all]', { open: false })

    // Bind listeners for collapsing module navigation items
    var moduleStructureElements = document.querySelectorAll('.module-structure');
    forEach(moduleStructureElements, function (moduleStructure) {
        jtd.addEvent(moduleStructure, 'click', function (e) {
            var originalTarget = e.target || e.srcElement || e.originalTarget;
            if (originalTarget.tagName !== 'A') { return; }

            var parentListItem = originalTarget.closest('li');
            if (parentListItem.className.indexOf('folder') === -1) { return; }

            toggleChildModuleList(parentListItem)
            e.preventDefault();
        });
    })

    var toggleChildModuleList = function (parent) {
        var list = parent.querySelector('ul');
        if (!list) {
            return;
        }
        list.classList.toggle('open');
        // Recursively automatically open any nested lists of size 1
        if (list.children.length === 1) {
            toggleChildModuleList(list.children[0])
        }
    }
});
