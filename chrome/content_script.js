/*global alert*/
(function () {

    function sendRequest(request, callback) {
        chrome.extension.sendRequest(request, function (response) {
            if (response.error) {
                alert("Octokey: " + response.error);
            } else if (callback) {
                callback(response);
            }
        });
    }

    var octokey_forms = jQuery('form.ajax-form');

    if (octokey_forms.length) {
        sendRequest({message: 'show_page_action'});

        octokey_forms.each(function () {
            var form = $(this),
                challenge_url = form.find('.octokey-challenge-url').val();

            form.find('input[name=session_key]').change(function (e) {
                var username  = form.find('input[name=session_key]'),
                    auth_request = form.find('input[name=session_password]');

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
                    } else if (response.handshake_id) {
                        var div = $('<div/>');
                        div.appendTo('body').qrcode("" + response.handshake_id);
                        sendRequest({
                            message: 'await_handshake',
                            handshake_id: response.handshake_id
                        }, function (response) {
                            auth_request.val(response.auth_request);
                            div.remove();
                        });
                    } else {
                        alert('got unexpected response: ' + JSON.stringify(response));

                    }
                });
            });

        });
    }
}());
