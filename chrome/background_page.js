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
        var ret = cache[url] || jQuery.get(url).then(function (response) {
            return response;
        });
        delete cache[url];
        return ret;
    };

    return _public;
}

var challenge_cache = challengeCache();

var pusher = new Pusher("427a8908c6541ab6f357");
var channel = pusher.subscribe('remote-response');
var open_intent = null;
var private_key;

function actionHandler(request, sender, sendResponse) {

    var _public = {};

    function challengeUrl() {
        return jQuery.absolutify(request.challenge_url, {
            relative_to: sender.tab.url,
            enforce_same_origin: true
        });
    }

    function privateKey() {
        if (!private_key) {
            private_key = octokey.privateKey(localStorage['private-key']);
        }
        return private_key;
    }

    function openIntent() {
        if (open_intent) {
            open_intent.reject();
        }
        chrome.tabs.sendMessage(sender.tab.id, {
            message: 'show_intent'
        });
        open_intent = jQuery.Deferred().always(function () {
            chrome.tabs.sendMessage(sender.tab.id, {
                message: 'hide_intent'
            });
        });
        return open_intent;
    }

    _public.show_page_action = function () {
        chrome.pageAction.show(sender.tab.id);
    };

    _public.fetch_challenge = function () {
        challenge_cache.fetch(challengeUrl());
    };

    _public.create_auth_request = function () {
        if (privateKey().passphrase_required) {
            openIntent().then(_public.create_auth_request);
        } else {
            challenge_cache.get(challengeUrl()).then(function (challenge) {

                try {
                    var auth_request = octokey.authRequest({
                            username: request.username,
                            challenge: challenge,
                            request_url: sender.tab.url
                        });

                    if (!auth_request.sign(privateKey())) {
                        throw "Could not sign auth request...";
                    } else {
                        sendResponse({
                            auth_request: auth_request.toBase64()
                        });
                    }
                } catch (e) {
                    sendResponse({error: e.toString()});
                }
            });
        }
    };

    _public.login_from_intent = function () {
        if (privateKey().setPassphrase(request.passphrase)) {
            open_intent.resolve();
        } else {
            sendResponse({error: "incorrect passphrase"});
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

        var conversion = octokey.privateKey.convert(request.private_key, request.current_passphrase, request.new_passphrase);

        if (conversion.errors) {
            sendResponse({error: conversion.errors.join("\n")});
        } else {
            localStorage['private-key'] = conversion.pem;
            sendResponse({ok: true});
        }

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
