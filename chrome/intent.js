/*global alert*/
jQuery(function ($) {
    var x = $('form').submit(function () {
        chrome.extension.sendRequest({
            message: 'login_from_intent',
            passphrase: $('input').val()
        }, function (response) {
            if (response.error) {
                alert('Octokey: ' + response.error);
            }
        });
        return false;
    });
});
