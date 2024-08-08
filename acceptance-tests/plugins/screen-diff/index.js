(function () {
    var settings = allure.getPluginSettings('screen-diff', { diffType: 'diff' });

    function renderImage(src) {
        return (
            '<div class="screen-diff__container">' +
            '<img class="screen-diff__image" src="' +
            src +
            '">' +
            '</div>'
        );
    }

    function findImage(data, name) {
        if (data.testStage && data.testStage.attachments) {
            var matchedImage = data.testStage.attachments.filter(function (attachment) {
                return attachment.name === name;
            })[0];
            if (matchedImage) {
                return 'data/attachments/' + matchedImage.source;
            }
        }
        return null;
    }

    function renderDiffContent(type, diffImage, actualImage, expectedImage) {
        if (type === 'diff') {
            if (diffImage) {
                return renderImage(diffImage);
            }
        }
        if (type === 'overlay' && expectedImage) {
            return (
                '<div class="screen-diff__overlay screen-diff__container">' +
                '<img class="screen-diff__image" src="' +
                expectedImage +
                '">' +
                '<div class="screen-diff__image-over">' +
                '<img class="screen-diff__image" src="' +
                actualImage +
                '">' +
                '</div>' +
                '</div>'
            );
        }
        if (actualImage) {
            return renderImage(actualImage);
        }
        return 'No diff data provided';
    }

    var TestResultView = Backbone.Marionette.View.extend({
        regions: {
            subView: '.screen-diff-view',
        },
        template: function () {
            return '<div class="screen-diff-view"></div>';
        },
        onRender: function () {
            var data = this.model.toJSON();
            var testType = data.labels.filter(function (label) {
                return label.name === 'testType';
            })[0];
            var diffImage = findImage(data, 'diff');
            var actualImage = findImage(data, 'actual');
            var expectedImage = findImage(data, 'expected');
            if (!testType || testType.value !== 'screenshotDiff') {
                return;
            }
            this.showChildView(
                'subView',
                new ScreenDiffView({
                    diffImage: diffImage,
                    actualImage: actualImage,
                    expectedImage: expectedImage,
                }),
            );
        },
    });
    var ErrorView = Backbone.Marionette.View.extend({
        templateContext: function () {
            return this.options;
        },
        template: function (data) {
            return '<pre class="screen-diff-error">' + data.error + '</pre>';
        },
    });
    var AttachmentView = Backbone.Marionette.View.extend({
        regions: {
            subView: '.screen-diff-view',
        },
        template: function () {
            return '<div class="screen-diff-view"></div>';
        },
        onRender: function () {
            jQuery
                .getJSON(this.options.sourceUrl)
                .then(this.renderScreenDiffView.bind(this), this.renderErrorView.bind(this));
        },
        renderErrorView: function (error) {
            console.log(error);
            this.showChildView(
                'subView',
                new ErrorView({
                    error: error.statusText,
                }),
            );
        },
        renderScreenDiffView: function (data) {
            this.showChildView(
                'subView',
                new ScreenDiffView({
                    diffImage: data.diff,
                    actualImage: data.actual,
                    expectedImage: data.expected,
                }),
            );
        },
    });

    var ScreenDiffView = Backbone.Marionette.View.extend({
        className: 'pane__section',
        events: function () {
            return {
                ['click [name="screen-diff-type-' + this.cid + '"]']: 'onDiffTypeChange',
                'mousemove .screen-diff__overlay': 'onOverlayMove',
            };
        },
        initialize: function (options) {
            this.diffImage = options.diffImage;
            this.actualImage = options.actualImage;
            this.expectedImage = options.expectedImage;
            this.radioName = 'screen-diff-type-' + this.cid;
        },
        templateContext: function () {
            return {
                diffType: settings.get('diffType'),
                diffImage: this.diffImage,
                actualImage: this.actualImage,
                expectedImage: this.expectedImage,
                radioName: this.radioName,
            };
        },
        template: function (data) {
            if (!data.diffImage && !data.actualImage && !data.expectedImage) {
                return '';
            }

            return (
                '<h3 class="pane__section-title">Screen Diff</h3>' +
                '<div class="screen-diff__content">' +
                '<div class="screen-diff__switchers">' +
                '<label><input type="radio" name="' +
                data.radioName +
                '" value="diff"> Show diff</label>' +
                '<label><input type="radio" name="' +
                data.radioName +
                '" value="overlay"> Show overlay</label>' +
                '</div>' +
                renderDiffContent(
                    data.diffType,
                    data.diffImage,
                    data.actualImage,
                    data.expectedImage,
                ) +
                '</div>'
            );
        },
        adjustImageSize: function (event) {
            var overImage = this.$(event.target);
            overImage.width(overImage.width());
        },
        onRender: function () {
            const diffType = settings.get('diffType');
            this.$('[name="' + this.radioName + '"][value="' + diffType + '"]').prop(
                'checked',
                true,
            );
            if (diffType === 'overlay') {
                this.$('.screen-diff__image-over img').on('load', this.adjustImageSize.bind(this));
            }
        },
        onOverlayMove: function (event) {
            var pageX = event.pageX;
            var containerScroll = this.$('.screen-diff__container').scrollLeft();
            var elementX = event.currentTarget.getBoundingClientRect().left;
            var delta = pageX - elementX + containerScroll;
            this.$('.screen-diff__image-over').width(delta);
        },
        onDiffTypeChange: function (event) {
            settings.save('diffType', event.target.value);
            this.render();
        },
    });
    allure.api.addTestResultBlock(TestResultView, { position: 'before' });
    allure.api.addAttachmentViewer('application/vnd.allure.image.diff', {
        View: AttachmentView,
        icon: 'fa fa-exchange',
    });
})();
