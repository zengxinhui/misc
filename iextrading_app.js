// ==UserScript==
// @name         iextrading
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  try to take over the world!
// @author       You
// @match        https://iextrading.com/apps/stocks/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    var customHeight=1400;
    var $=window.jQuery;

    var observer = new MutationObserver(check);
    observer.observe(document, {childList: true, subtree: true});

    function check(changes, observer) {
        if($('div.slick-viewport').length>0) {
            $('div.slick-viewport').height(customHeight);
            $('div.ui-widget').height(customHeight);
            observer.disconnect();
        }
    }
})();
