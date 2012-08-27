/*global alert*/
(function () {

    var passphrase_dialog = (function () {
        var _public = {}, node = null;

        _public.show = function () {
            if (node) {
                return;
            }

            var url = chrome.extension.getURL("/intent.html");
            node = jQuery('<iframe style="top: 0; left: 0; width: 100%; height: 100%; position: fixed;" src="' + url + '">');
            node.appendTo('body');
        };

        _public.hide = function () {
            node.detach();
            node = null;
        };

        return _public;
    }()),
        octokey_forms = jQuery('form.octokey');

    function actionHandler(request, sender, sendResponse) {
        var _public = {};

        _public.show_intent = passphrase_dialog.show;
        _public.hide_intent = passphrase_dialog.hide;

        return _public;
    }

    chrome.extension.onMessage.addListener(function (request, sender, sendResponse) {

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

    function sendRequest(request, callback) {
        chrome.extension.sendRequest(request, function (response) {
            if (response.error) {
                alert("Octokey: " + response.error);
            } else if (callback) {
                callback(response);
            }
        });
    }

    if (octokey_forms.length) {
        sendRequest({message: 'show_page_action'});

        octokey_forms.each(function () {
            var form = $(this),
                challenge_url = form.find('.octokey-challenge-url').val();

            form.submit(function (e) {
                var username  = form.find('input.octokey-username'),
                    auth_request = form.find('input.octokey-auth-request');

                if (!username.val()) {
                    return;
                }

                if (auth_request.val()) {
                    return;
                }

                e.preventDefault();
                e.stopPropagation();

                sendRequest({
                    message: 'create_auth_request',
                    username: username.val(),
                    challenge_url: challenge_url
                }, function (response) {
                    if (response.auth_request) {
                        auth_request.val(response.auth_request);
                        form.submit();
                    } else if (response.handshake_id) {
                        var div = $('<div/>').css({
                            position: 'fixed',
                            top: '50%',
                            left: '50%',
                            'margin-top': '-175px',
                            'margin-left': '-175px',
                            padding: '50px',
                            'border-radius': '10px',
                            'background-color': 'white',
                            'box-shadow': '0 0 20px rgba(0, 0, 0, 0.2)'
                        }),
                            mask = $('<div/>').css({
                            'background-color': 'rgba(255,255,255, 0.6)',
                            position: 'fixed',
                            top: 0,
                            left: 0,
                            height: '100%',
                            width: '100%'
                        });
                        mask.appendTo('body');
                        div.appendTo(mask);
                        div.qrcode("" + response.handshake_id);
                        sendRequest({
                            message: 'await_handshake',
                            handshake_id: response.handshake_id
                        }, function (response) {
                            auth_request.val(response.auth_request);
                            form.submit();
                            div.remove();
                        });
                    } else {
                        //alert('got unexpected response: ' + JSON.stringify(response));

                    }
                });
            });

        });
    }
}());
