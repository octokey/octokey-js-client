(function () {
    var octokey_forms = jQuery('form.octokey');

    if (octokey_forms.length) {
        chrome.extension.sendRequest({message: 'show_page_action'});

        octokey_forms.each(function () {
            var form = $(this),
                challenge_url = form.find('.octokey-challenge-url').val();

            form.append('<input type="hidden" class="octokey-signature" name="octokey-signature"/>');
            chrome.extension.sendRequest({message: 'fetch_challenge',
                                          challenge_url: challenge_url});
            this.addEventListener('submit', function (e) {
                var username  = form.find('.octokey-username').val(),
                    signature = form.find('.octokey-signature').val();

                if (signature) {
                    return;
                }

                e.preventDefault();
                e.stopPropagation();

                chrome.extension.sendRequest({
                    message: 'create_signature',
                    username: username
                }, function (response) {
                    form.find('.octokey-signature').val(response.signature);
                    form.submit();
                });
            }, true);
        });
    }
}());
