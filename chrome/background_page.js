/*global alert, Pusher*/
function challengeCache() {
    var _public = {},
        cache = {};

    _public.fetch = function (url) {
        if (!cache[url]) {
            cache[url] = _public.get(url);
        }
    };

    _public.get = function (url) {
        return {
            then: function (cb) {
                cb("DOO");
            }
        };
    };

    return _public;
}

var challenge_cache = challengeCache();

var pusher = new Pusher("427a8908c6541ab6f357");
var channel = pusher.subscribe('remote-response');

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
        var challenge = "FOO",
            // random 5-digit number.
            handshake_id = Math.floor(Math.random() * 90000) + 10000,
            to_sign = {
                username: request.username,
                challenge: challenge,
                request_url: sender.tab.url
            };

        try {
            if (request.username === 'bruce@test.linkedin.com') {
                jQuery.post("https://octokey.herokuapp.com/local/" + handshake_id, to_sign);
                sendResponse({
                    handshake_id: handshake_id
                });
            } else {
                sendResponse({
                    auth_request: privateKey().authRequest64(to_sign)
                });
            }
        } catch (e) {
            sendResponse({error: e.toString()});
        }
    };

    _public.await_handshake = function () {
        channel.bind(request.handshake_id, function (data) {
            channel.unbind(request.handshake_id);
            sendResponse({
                auth_request: data.auth_request
            });
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
