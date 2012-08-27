describe('octokey.authRequest', function () {

    var private_key, private_key_pem = [
        '-----BEGIN PRIVATE KEY-----',
        'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCsJAbbXe63OoTl',
        'hWNNUXl7EZEKQT064zssKn8U6492gesVReTLYxBzB/b0ncDiLzPGkRL1F1IRTqIg',
        'SyjD3zAiLTHX8ud/HqMbljT+JCwbU1GU0IJrJ0a8ZoL4/DBaLBhFzs+0GBXgo4BV',
        'cxl0wHmcVFp6RDWSx0f/frQoIaCWM+3NM2XT173tAHAcUhnd5rkSKH8eKt5OtFKe',
        '8X7LCbC7Ffi5sOvRl5Jx64XZLlYtcfb5NXQtRvZjEXLfAcMzhl/AEHlT3FmGQhvN',
        'IvX0zvHwt4Qbce4MOfAR9T3fI5ir2XfO6cJoQbg22Inakdic3pMohCiebrSlWb1+',
        'dG+xus4nAgMBAAECggEAUmZQbfNx0H2PnfqSxTEJ8JJBFmKSN70L1yFkgZQcsUKR',
        'UDaLxZvfBOE8Im3dJagopZVOOMn3+9bjHog7tD8C4Gk34cIhdCUrOIpXRYv1HQNu',
        'GskQlNBRON/tM9gsIQ3YdJoBrJiW6Ff7l2uoNM3pqJ5sTPiXmHISEcgJ3ufx4dOi',
        'rRZZcuA4RI5H4xE19rBK+eqDpYdBNGK+/FDwRdhGrUQcwXg0sp16qwZP0Vmzg+4D',
        'kauO/BfC1w7fedpQlHUfjoZ49+PPDk2p17YJXnSM8W5JizrxNMDhiD6w8Ntdxs7k',
        'rMbNhrXseNlKYYwd47l2D53CnC0txshuAoGy5/GDYQKBgQDWd++5mXRNVwLUbn37',
        'HTef2aN1bNwSMUeC8hOt99uhwvUig0BAPlepINSEh++a4KcmQNV45upytoqQxxIw',
        'OjhTMmgy8H1ll8ayR4zMvLtCKLSMfKXJVzLxHweW4DvEdFo2RtHZZi84OS5CUNvN',
        '57wuR8d7bFuNhwrahUhXH+K1MQKBgQDNebukg8DPWKknCh84Vhtl4L4MzSbjEJ8s',
        'mOYJXsA/ch6up4kTnRbzt5fE+VQrjKBzWfluvT6EawJlCZ20lqG3sCKBbxMijyeQ',
        'F84/Ls6t1MOxE9q9IS9Byi5+TbEXi/4bAlDmZH/W92AbkBamNqdFipKh3pZjh7j5',
        'Oi4ugf5C1wKBgEtTcKU1Wn3Xc6z86c6K4oCIRjr18w2ItV8ueu79QOy9tq9affSS',
        'cON8Hmg1/lfdU5fB6bg/ElUb++sBoEfECwhdie9qPAC0oBr5umAmYXbJKTC2jtv6',
        'fm/lwBqjwxoq64xor0e19hu/KZotICZfn955Y3zcAAPjTFKXwWKoVk3hAoGAVepf',
        'vnNkzI4q9Gr0EO9YN2oYrWuepfUOSWyJS0O2KRFDqQ3ecDgQH8oViMQkIK2FbZYi',
        'iN5SZLYF4095BMizSAY691oFaz7mcQazM5IT03WSedlubgSRKPYsKJ29vbXIg2yd',
        'fShql+0J35yJC+jwWlCN7WcQBP/8JSHhq4qpUTMCgYAN8yM5Dk6Nt+VUB+voued/',
        '86g7lvH0vj/fC2MJuUjNJMdg/TYLIRm23Pk0e9nFuqbnwxWqvxJqpQd3/6Rhd0xW',
        'QySQZqr+cbkeszgaW6sohx+FMDc2MHxnyGvcpom4YXkwTTk9thWJ1Cu/VVenQ0kF',
        'ncK1GzU47lgOUzeEtLqGbg==',
        '-----END PRIVATE KEY-----'
    ].join('\n');

    beforeEach(function () {
        private_key = octokey.privateKey(private_key_pem);
    });

    it('should check the type of the challenge', function () {
        var auth_request = octokey.authRequest({
            challenge: {foo: 'bar'},
            request_url: 'https://www.example.com/login',
            username: 'foo'
        });
        expect(auth_request.isValid()).toBe(false);
        expect(auth_request.errors()).toContain('challenge is not a string');
    });

    it('should check the length of the challenge', function () {
        var auth_request = octokey.authRequest({
            challenge: 'AAAA',
            request_url: 'https://www.example.com/login',
            username: 'foo'
        });
        expect(auth_request.isValid()).toBe(false);
        expect(auth_request.errors()).toContain('challenge is too short');
    });

    it('should should only accept base64 challenges', function () {
        var auth_request = octokey.authRequest({
            challenge: "Isn't punctu@tion fun?! Have lots of it: %^&$!<>!",
            request_url: 'https://www.example.com/login',
            username: 'foo'
        });
        expect(auth_request.isValid()).toBe(false);
        expect(auth_request.errors()).toContain('challenge contains invalid characters, must be base64');
    });

    it('should check that request_url is a web URL', function () {
        var auth_request = octokey.authRequest({
            challenge: 'KWm5PMQC3UYSFY/xgLimHvLhLcuIdwRZoDm4UfEADO0=',
            request_url: 'urn:isbn:0-34-539180-2',
            username: 'foo'
        });
        expect(auth_request.isValid()).toBe(false);
        expect(auth_request.errors()).toContain('request_url is not valid');
    });

    it('should encode non-ascii request_url and username chars as utf-8', function () {
        var auth_request = octokey.authRequest({
            challenge: 'KWm5PMQC3UYSFY/xgLimHvLhLcuIdwRZoDm4UfEADO0=',
            request_url: 'http://\u043F\u0440\u0435\u0437\u0438\u0434\u0435\u043D\u0442.\u0440\u0444/\u0444\u043E\u0442\u043E',
            username: '\u0412\u043B\u0430\u0434\u0438\u0301\u043C\u0438\u0440'
        });
        expect(auth_request.isValid()).toBe(true);
        auth_request.sign(private_key);
        expect(forge.util.bytesToHex(auth_request.toBytes())).toMatch(new RegExp(['^',
            '00000020', '2969b93cc402dd4612158ff180b8a61ef2e12dcb88770459a039b851f1000ced', // challenge
            '00000027', '687474703a2f2fd0bfd180d0b5d0b7d0b8d0b4d0b5d0bdd1822ed180d1842fd184d0bed182d0be', // request_url
            '00000012', 'd092d0bbd0b0d0b4d0b8cc81d0bcd0b8d180' // username
        ].join('')));
    });

    it('should check the type of the username', function () {
        var auth_request = octokey.authRequest({
            challenge: 'KWm5PMQC3UYSFY/xgLimHvLhLcuIdwRZoDm4UfEADO0=',
            request_url: 'https://www.example.com/login',
            username: document.createElement('input')
        });
        expect(auth_request.isValid()).toBe(false);
        expect(auth_request.errors()).toContain('username is not a string');
    });

    it('should check the length of the username', function () {
        var auth_request = octokey.authRequest({
            challenge: 'KWm5PMQC3UYSFY/xgLimHvLhLcuIdwRZoDm4UfEADO0=',
            request_url: 'https://www.example.com/login',
            username: ''
        });
        expect(auth_request.isValid()).toBe(false);
        expect(auth_request.errors()).toContain('username is too short');
    });

    it('should construct a request in the style of RFC4252', function () {
        var auth_request = octokey.authRequest({
            challenge: 'KWm5PMQC3UYSFY/xgLimHvLhLcuIdwRZoDm4UfEADO0=',
            request_url: 'https://www.example.com/login',
            username: 'foo'
        });
        expect(auth_request.isValid()).toBe(true);
        auth_request.sign(private_key);
        expect(forge.util.bytesToHex(auth_request.toBytes())).toBe([
            '00000020', '2969b93cc402dd4612158ff180b8a61ef2e12dcb88770459a039b851f1000ced', // challenge
            '0000001d', '68747470733a2f2f7777772e6578616d706c652e636f6d2f6c6f67696e',       // 'https://www.example.com/login'
            '00000003', '666f6f',                                                           // 'foo'
            '0000000c', '6f63746f6b65792d61757468',                                         // 'octokey-auth'
            '00000009', '7075626c69636b6579',                                               // 'publickey'
            '00000007', '7373682d727361',                                                   // 'ssh-rsa'
            '00000117', '00000007', '7373682d727361',   // public key format: 'ssh-rsa'
                        '00000003', '010001',           // public key exponent
                        '00000101', '00ac2406db5deeb73a84e585634d51797b11910a413d3ae33b2c2a7f14eb8f76', // public key modulus
                                    '81eb1545e4cb63107307f6f49dc0e22f33c69112f51752114ea2204b28c3df30',
                                    '222d31d7f2e77f1ea31b9634fe242c1b535194d0826b2746bc6682f8fc305a2c',
                                    '1845cecfb41815e0a38055731974c0799c545a7a443592c747ff7eb42821a096',
                                    '33edcd3365d3d7bded00701c5219dde6b912287f1e2ade4eb4529ef17ecb09b0',
                                    'bb15f8b9b0ebd1979271eb85d92e562d71f6f935742d46f6631172df01c33386',
                                    '5fc0107953dc5986421bcd22f5f4cef1f0b7841b71ee0c39f011f53ddf2398ab',
                                    'd977cee9c26841b836d889da91d89cde932884289e6eb4a559bd7e746fb1bace27',
            '0000010f', '00000007', '7373682d727361',   // signature algorithm: 'ssh-rsa'
                        '00000100', '9892ff5c1b84d2b32c8bf6ea48335d659065ef0eef5f66e755a6397725bd5b08', // signature
                                    '4679d09bb47ee7ce347dff91acbbb41a3d334fdb861a50d07bdce18b7dc268f0',
                                    '8091dd66b9f9c232fcbdfc3d6391b092408c9d320bd16fe2678b8cda9cf54183',
                                    '579dc7a707322b5e5627a20edefa9a6bcd519ea9ab7d9bd9133ab3250d4c13a2',
                                    'b5472540367bdc5abb26a2c48d8e97b6b41ca1461870e087b1ce7273cac06756',
                                    '16f996eaa0c2c5d41086bbfe1419075d5308d9eaa9299f06921f54b51cc92398',
                                    '948ee2317967a3b90a8d3dd64c5add95e0545c6a9ea43a5130e6b28b54313641',
                                    '7e03470ee00a6907b2da6054e7290792b4c7a1ec99e2f81532a86bb7428c5ef2'
        ].join(''));
    });
});
