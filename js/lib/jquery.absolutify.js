/*global window, */
/*jslint regexp: false */

(function ($) {

    function protocol(base) {
        var match = base.match(/^([a-z]+:)\/\//i);
        if (match) {
            return match[1];
        } else {
            throw new TypeError("$.absolutify called with invalid relative_to: " + base);
        }
    }

    function server(base) {
        var match = base.match(/^([a-z]+:\/\/[a-z0-9\-\.:]+)/i);
        if (match) {
            return match[1];
        } else {
            throw new TypeError("$.absolutify called with invalid relative_to: " + base);
        }
    }

    function directory(base) {
        var match = base.match(/^([a-zA-Z]+:\/\/[^?#]+\/)/i);
        return match ? match[1] : (server(base) + "/");
    }

    $.absolutify = function (url, opts) {

        var relative_to = opts && opts.relative_to || window.location.toString(),
            ret;

        switch (url.charAt(0)) {

        case '#':
            // http://example.com/index.html#section1 links to #section2
            //      -> http://example.com#index.html#section2
            ret = relative_to.replace(/#.*$/, '') + url;
            break;

        case '?':
            // http://example.com/index.cgi?q=search#end links to ?q=search&page=2
            //      -> http://example.com/index.cgi?q=search&page=2
            ret = relative_to.replace(/[?#].*$/, '') + url;
            break;

        case '/':
            // https://bank.example.com/ links to //subsystem.bank.example.com
            //      -> https://subsystem.bank.example.com

            // http://example.com/wiki/AC/DC links to /login
            //      -> http://example.com/login
            ret = (url.charAt(1) === '/' ? protocol : server)(relative_to) + url;
            break;

        default:
            // http://example.com/music/album.html links to track3.html
            //      -> http://example.com/music/track3.html
            if (!/^[a-z]+:/i.test(url)) {
                ret = directory(relative_to) + url;

            // http://zim.example.com/ links to http://blah.example.org/
            //      -> http://blah.example.org/
            } else {
                ret =  url;
            }
        }

        if (opts && opts.enforce_same_origin && server(relative_to) !== server(ret)) {
            throw "Got Origin mismatch: " + ret + " is not hosted on the same server as " + relative_to;
        } else {
            return ret;
        }
    };

    $.fn.absolutify = function (opts) {
        this.find("a").add(this.filter("a")).each(function () {
            $(this).attr('href', $.absolutify($(this).attr('href'), opts));
        });
        this.find("img").add(this.filter("img")).each(function () {
            $(this).attr('src', $.absolutify($(this).attr('src'), opts));
        });

        return this;
    };

}(jQuery));
