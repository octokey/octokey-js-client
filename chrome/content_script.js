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

    var octokey_forms = jQuery('form.octokey');

    if (octokey_forms.length) {
        sendRequest({message: 'show_page_action'});

        octokey_forms.each(function () {
            var form = $(this),
                challenge_url = form.find('.octokey-challenge-url').val();

            form.append('<input type="hidden" class="octokey-auth-request" name="octokey-auth-request"/>');
            sendRequest({message: 'fetch_challenge',
                                          challenge_url: challenge_url});
            this.addEventListener('submit', function (e) {
                var username  = form.find('.octokey-username').val(),
                    auth_request = form.find('.octokey-auth-request').val();

                if (auth_request) {
                    return;
                }

                e.preventDefault();
                e.stopPropagation();

                sendRequest({
                    message: 'create_auth_request',
                    username: username,
                    challenge_url: challenge_url
                }, function (response) {
                    form.find('.octokey-auth-request').val(response.auth_request);
                    form.submit();
                });
            }, true);
        });
    }
}());
