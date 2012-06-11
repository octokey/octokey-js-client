/*global alert*/
$(function () {
    if (!localStorage['private-key']) {
        $('div.first-use').show();
    } else {
        $('div.public-keys').show();
    }

    $('.private-key-form').submit(function () {
        chrome.extension.sendRequest({
            message: 'set_private_key',
            private_key: $('.private-key').val()
        }, function (response) {
            if (response.ok) {
                $('div.public-keys').show();
                $('div.first-use').hide();
            } else {
                alert(response.error);
            }
        });

        return false;
    });
});
