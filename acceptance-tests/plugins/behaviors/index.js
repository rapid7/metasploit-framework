'use strict';

allure.api.addTranslation('en', {
    tab: {
        behaviors: {
            name: 'Behaviors'
        }
    },
    widget: {
        behaviors: {
            name: 'Features by stories',
            showAll: 'show all'
        }
    }
});

allure.api.addTranslation('ru', {
    tab: {
        behaviors: {
            name: 'Функциональность'
        }
    },
    widget: {
        behaviors: {
            name: 'Функциональность',
            showAll: 'показать все'
        }
    }
});

allure.api.addTranslation('zh', {
    tab: {
        behaviors: {
            name: '功能'
        }
    },
    widget: {
        behaviors: {
            name: '特性场景',
            showAll: '显示所有'
        }
    }
});

allure.api.addTranslation('de', {
    tab: {
        behaviors: {
            name: 'Verhalten'
        }
    },
    widget: {
        behaviors: {
            name: 'Features nach Stories',
            showAll: 'Zeige alle'
        }
    }
});

allure.api.addTranslation('nl', {
    tab: {
        behaviors: {
            name: 'Functionaliteit'
        }
    },
    widget: {
        behaviors: {
            name: 'Features en story’s',
            showAll: 'Toon alle'
        }
    }
});

allure.api.addTranslation('he', {
    tab: {
        behaviors: {
            name: 'התנהגויות'
        }
    },
    widget: {
        behaviors: {
            name: 'תכונות לפי סיפורי משתמש',
            showAll: 'הצג הכול'
        }
    }
});

allure.api.addTranslation('br', {
    tab: {
        behaviors: {
            name: 'Comportamentos'
        }
    },
    widget: {
        behaviors: {
            name: 'Funcionalidades por história',
            showAll: 'Mostrar tudo'
        }
    }
});

allure.api.addTranslation('ja', {
    tab: {
        behaviors: {
            name: '振る舞い'
        }
    },
    widget: {
        behaviors: {
            name: 'ストーリー別の機能',
            showAll: '全て表示'
        }
    }
});

allure.api.addTranslation('es', {
    tab: {
        behaviors: {
            name: 'Funcionalidades'
        }
    },
    widget: {
        behaviors: {
            name: 'Funcionalidades por Historias de Usuario',
            showAll: 'mostrar todo'
        }
    }
});

allure.api.addTranslation('kr', {
    tab: {
        behaviors: {
            name: '동작'
        }
    },
    widget: {
        behaviors: {
            name: '스토리별 기능',
            showAll: '전체 보기'
        }
    }
});

allure.api.addTranslation('fr', {
    tab: {
        behaviors: {
            name: 'Comportements'
        }
    },
    widget: {
        behaviors: {
            name: 'Thèmes par histoires',
            showAll: 'Montrer tout'
        }
    }
});

allure.api.addTranslation('pl', {
    tab: {
        behaviors: {
            name: 'Zachowania'
        }
    },
    widget: {
        behaviors: {
            name: 'Funkcje według historii',
            showAll: 'pokaż wszystko'
        }
    }
});

allure.api.addTranslation('az', {
    tab: {
        behaviors: {
            name: 'Davranışlar'
        }
    },
    widget: {
        behaviors: {
            name: 'Hekayələr üzrə xüsusiyyətlər',
            showAll: 'hamısını göstər'
        }
    }
});

allure.api.addTab('behaviors', {
    title: 'tab.behaviors.name', icon: 'fa fa-list',
    route: 'behaviors(/)(:testGroup)(/)(:testResult)(/)(:testResultTab)(/)',
    onEnter: (function (testGroup, testResult, testResultTab) {
        return new allure.components.TreeLayout({
            testGroup: testGroup,
            testResult: testResult,
            testResultTab: testResultTab,
            tabName: 'tab.behaviors.name',
            baseUrl: 'behaviors',
            url: 'data/behaviors.json',
            csvUrl: 'data/behaviors.csv'
        });
    })
});

allure.api.addWidget('widgets', 'behaviors', allure.components.WidgetStatusView.extend({
    rowTag: 'a',
    title: 'widget.behaviors.name',
    baseUrl: 'behaviors',
    showLinks: true
}));
