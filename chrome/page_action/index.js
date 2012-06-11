$(function () {
    if (!localStorage['private-key']) {
        $('div.first-use').show();
    } else {
        $('div.public-keys').show();
    }

    $('.private-key-form').submit(function () {
        localStorage['private-key'] = $('.private-key').val();
        $('div.public-keys').show();
        $('div.first-use').hide();
    });
});
