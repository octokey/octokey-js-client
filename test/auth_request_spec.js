describe('octokey.authRequest', function () {

    var private_key, private_key_pem = [
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEogIBAAKCAQEArCQG213utzqE5YVjTVF5exGRCkE9OuM7LCp/FOuPdoHrFUXk',
        'y2MQcwf29J3A4i8zxpES9RdSEU6iIEsow98wIi0x1/Lnfx6jG5Y0/iQsG1NRlNCC',
        'aydGvGaC+PwwWiwYRc7PtBgV4KOAVXMZdMB5nFRaekQ1ksdH/360KCGgljPtzTNl',
        '09e97QBwHFIZ3ea5Eih/HireTrRSnvF+ywmwuxX4ubDr0ZeSceuF2S5WLXH2+TV0',
        'LUb2YxFy3wHDM4ZfwBB5U9xZhkIbzSL19M7x8LeEG3HuDDnwEfU93yOYq9l3zunC',
        'aEG4NtiJ2pHYnN6TKIQonm60pVm9fnRvsbrOJwIDAQABAoIBAFJmUG3zcdB9j536',
        'ksUxCfCSQRZikje9C9chZIGUHLFCkVA2i8Wb3wThPCJt3SWoKKWVTjjJ9/vW4x6I',
        'O7Q/AuBpN+HCIXQlKziKV0WL9R0DbhrJEJTQUTjf7TPYLCEN2HSaAayYluhX+5dr',
        'qDTN6aiebEz4l5hyEhHICd7n8eHToq0WWXLgOESOR+MRNfawSvnqg6WHQTRivvxQ',
        '8EXYRq1EHMF4NLKdeqsGT9FZs4PuA5GrjvwXwtcO33naUJR1H46GePfjzw5Nqde2',
        'CV50jPFuSYs68TTA4Yg+sPDbXcbO5KzGzYa17HjZSmGMHeO5dg+dwpwtLcbIbgKB',
        'sufxg2ECgYEA1nfvuZl0TVcC1G59+x03n9mjdWzcEjFHgvITrffbocL1IoNAQD5X',
        'qSDUhIfvmuCnJkDVeObqcraKkMcSMDo4UzJoMvB9ZZfGskeMzLy7Qii0jHylyVcy',
        '8R8HluA7xHRaNkbR2WYvODkuQlDbzee8LkfHe2xbjYcK2oVIVx/itTECgYEAzXm7',
        'pIPAz1ipJwofOFYbZeC+DM0m4xCfLJjmCV7AP3IerqeJE50W87eXxPlUK4ygc1n5',
        'br0+hGsCZQmdtJaht7AigW8TIo8nkBfOPy7OrdTDsRPavSEvQcoufk2xF4v+GwJQ',
        '5mR/1vdgG5AWpjanRYqSod6WY4e4+TouLoH+QtcCgYBLU3ClNVp913Os/OnOiuKA',
        'iEY69fMNiLVfLnru/UDsvbavWn30knDjfB5oNf5X3VOXwem4PxJVG/vrAaBHxAsI',
        'XYnvajwAtKAa+bpgJmF2ySkwto7b+n5v5cAao8MaKuuMaK9HtfYbvymaLSAmX5/e',
        'eWN83AAD40xSl8FiqFZN4QKBgFXqX75zZMyOKvRq9BDvWDdqGK1rnqX1DklsiUtD',
        'tikRQ6kN3nA4EB/KFYjEJCCthW2WIojeUmS2BeNPeQTIs0gGOvdaBWs+5nEGszOS',
        'E9N1knnZbm4EkSj2LCidvb21yINsnX0oapftCd+ciQvo8FpQje1nEAT//CUh4auK',
        'qVEzAoGADfMjOQ5OjbflVAfr6Lnnf/OoO5bx9L4/3wtjCblIzSTHYP02CyEZttz5',
        'NHvZxbqm58MVqr8SaqUHd/+kYXdMVkMkkGaq/nG5HrM4GlurKIcfhTA3NjB8Z8hr',
        '3KaJuGF5ME05PbYVidQrv1VXp0NJBZ3CtRs1OO5YDlM3hLS6hm4=',
        '-----END RSA PRIVATE KEY-----'
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
