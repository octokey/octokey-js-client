/*global alert*/
jQuery(function ($) {

    function sendRequest(request, callback) {
        chrome.extension.sendRequest(request, function (response) {
            if (response.error) {
                alert("Octokey: " + response.error);
            } else if (callback) {
                callback(response);
            }
        });
    }

    $(".private-key").val(localStorage['private-key']);

    $(".update-key").click(function () {
        sendRequest({
            message: 'set_private_key',
            private_key: $('.private-key').val(),
            current_passphrase: $('.current-passphrase').val(),
            new_passphrase: $('.new-passphrase').val()
        }, function () {
            alert('woo!');
        });
    });
});
