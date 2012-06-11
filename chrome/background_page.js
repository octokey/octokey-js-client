/*global alert*/
function challengeCache() {
    var _public = {},
        cache = {};

    _public.fetch = function (url) {
        if (!cache[url]) {
            cache[url] = _public.get(url);
        }
    };

    _public.get = function (url) {
        var ret = cache[url] || jQuery.getJSON(url).then(function (response) {
            return response.challenge;
        });
        delete cache[url];
        return ret;
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

    function privateKey() {
        if (!localStorage['private-key']) {
            throw "No private key set. Please click on the Octokey icon";
        }
        return octokey.privateKey(localStorage['private-key']);
    }

    _public.show_page_action = function () {
        chrome.pageAction.show(sender.tab.id);
    };

    _public.fetch_challenge = function () {
        challenge_cache.fetch(challengeUrl());
    };

    _public.create_auth_request = function () {
        challenge_cache.get(challengeUrl()).then(function (challenge) {
            try {
                sendResponse({
                    auth_request: privateKey().authRequest64({
                        username: request.username,
                        challenge: challenge
                    })
                });
            } catch (e) {
                sendResponse({error: e.toString()});
            }
        });
    };

    _public.public_key = function () {
        sendResponse({
            public_key: privateKey().publicKey()
        });
    };

    _public.set_private_key = function () {

        try {
            octokey.privateKey(request.private_key);
        } catch (e) {
            sendResponse({error: e.toString()});
            return;
        }

        localStorage['private-key'] = request.private_key;

        sendResponse({ok: true});
    };

    return _public;
}

chrome.extension.onRequest.addListener(function (request, sender, sendResponse) {

    var handler = actionHandler(request, sender, sendResponse);
    try {
        if (handler[request.message]) {
            handler[request.message]();
        } else {
            throw "Got unknown message: " + JSON.stringify(request);
        }
    } catch (e) {
        sendResponse({error: e.toString()});
    }
});
