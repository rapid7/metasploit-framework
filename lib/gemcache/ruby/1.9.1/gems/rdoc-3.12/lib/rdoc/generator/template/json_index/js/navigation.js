/*
 * Navigation allows movement using the arrow keys through the search results.
 *
 * When using this library you will need to set scrollIntoView to the
 * appropriate function for your layout.  Use scrollInWindow if the container
 * is not scrollable and scrollInElement if the container is a separate
 * scrolling region.
 */
Navigation = new function() {
  this.initNavigation = function() {
    var _this = this;

    $(document).keydown(function(e) {
      _this.onkeydown(e);
    }).keyup(function(e) {
      _this.onkeyup(e);
    });

    this.navigationActive = true;
  }

  this.setNavigationActive = function(state) {
    this.navigationActive = state;
    this.clearMoveTimeout();
  }

  this.onkeyup = function(e) {
    if (!this.navigationActive) return;

    switch(e.keyCode) {
      case 37: //Event.KEY_LEFT:
      case 38: //Event.KEY_UP:
      case 39: //Event.KEY_RIGHT:
      case 40: //Event.KEY_DOWN:
        this.clearMoveTimeout();
        break;
    }
  }

  this.onkeydown = function(e) {
    if (!this.navigationActive) return;
    switch(e.keyCode) {
      case 37: //Event.KEY_LEFT:
        if (this.moveLeft()) e.preventDefault();
        break;
      case 38: //Event.KEY_UP:
        if (e.keyCode == 38 || e.ctrlKey) {
          if (this.moveUp()) e.preventDefault();
          this.startMoveTimeout(false);
        }
        break;
      case 39: //Event.KEY_RIGHT:
        if (this.moveRight()) e.preventDefault();
        break;
      case 40: //Event.KEY_DOWN:
        if (e.keyCode == 40 || e.ctrlKey) {
          if (this.moveDown()) e.preventDefault();
          this.startMoveTimeout(true);
        }
        break;
      case 13: //Event.KEY_RETURN:
        if (this.$current)
          e.preventDefault();
          this.select(this.$current);
        break;
    }
    if (e.ctrlKey && e.shiftKey) this.select(this.$current);
  }

  this.clearMoveTimeout = function() {
    clearTimeout(this.moveTimeout);
    this.moveTimeout = null;
  }

  this.startMoveTimeout = function(isDown) {
    if (!$.browser.mozilla && !$.browser.opera) return;
    if (this.moveTimeout) this.clearMoveTimeout();
    var _this = this;

    var go = function() {
      if (!_this.moveTimeout) return;
      _this[isDown ? 'moveDown' : 'moveUp']();
      _this.moveTimout = setTimeout(go, 100);
    }
    this.moveTimeout = setTimeout(go, 200);
  }

  this.moveRight = function() {
  }

  this.moveLeft = function() {
  }

  this.move = function(isDown) {
  }

  this.moveUp = function() {
    return this.move(false);
  }

  this.moveDown = function() {
    return this.move(true);
  }

  /*
   * Scrolls to the given element in the scrollable element view.
   */
  this.scrollInElement = function(element, view) {
    var offset, viewHeight, viewScroll, height;
    offset = element.offsetTop;
    height = element.offsetHeight;
    viewHeight = view.offsetHeight;
    viewScroll = view.scrollTop;

    if (offset - viewScroll + height > viewHeight) {
      view.scrollTop = offset - viewHeight + height;
    }
    if (offset < viewScroll) {
      view.scrollTop = offset;
    }
  }

  /*
   * Scrolls to the given element in the window.  The second argument is
   * ignored
   */
  this.scrollInWindow = function(element, ignored) {
    var offset, viewHeight, viewScroll, height;
    offset = element.offsetTop;
    height = element.offsetHeight;
    viewHeight = window.innerHeight;
    viewScroll = window.scrollY;

    if (offset - viewScroll + height > viewHeight) {
      window.scrollTo(window.scrollX, offset - viewHeight + height);
    }
    if (offset < viewScroll) {
      window.scrollTo(window.scrollX, offset);
    }
  }
}

