function challengeCache() {
    var _public = {},
        cache = {};

    _public.fetch = function (url) {
        if (!cache[url]) {
            cache[url] = jQuery.getJSON(url).then(function (response) {
                return response.challenge;
            });
        }

        return cache[url];
    };

    return _public;
}

var challenge_cache = challengeCache();

function actionHandler(request, sender, sendResponse) {

    var _public = {};

    function challengeUrl() {
        return jQuery.absolutify(request.challenge_url, {
            relative_to: sender.tab.url,
            enforce_same_origin: true
        });
    }

    _public.show_page_action = function () {
        chrome.pageAction.show(sender.tab.id);
    };

    _public.fetch_challenge = function () {
        challenge_cache.fetch(challengeUrl());
    };

    _public.create_signature = function () {
        challenge_cache.fetch(challengeUrl()).then(function (challenge) {

        });
    };

    return _public;
}

chrome.extension.onRequest.addListener(function (request, sender, sendResponse) {

    var handler = actionHandler(request, sender, sendResponse);

    if (handler[request.message]) {
        handler[request.message]();
    } else {
        console.log("Got unknown message: " + JSON.stringify(request));
    }
});
