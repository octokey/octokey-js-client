describe('octokey.privateKey', function () {

    describe('with an unencrypted private key', function () {
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
        ].join('\r\n');

        beforeEach(function () {
            private_key = octokey.privateKey(private_key_pem);
        });

        it('should not require a passphrase', function () {
            expect(private_key.passphrase_required).toBe(false);
        });

        it('should ignore a passphrase being given', function () {
            expect(private_key.setPassphrase('rhubarb, rhubarb, rhubarb')).toBe(true);
        });

        it('should extract the public key from the private key', function () {
            expect(private_key.publicKey().toBase64()).toBe([
                'ssh-rsa ',
                'AAAAB3NzaC1yc2EAAAADAQABAAABAQCsJAbbXe63OoTlhWNNUXl7EZEKQT064zssKn8U64',
                '92gesVReTLYxBzB/b0ncDiLzPGkRL1F1IRTqIgSyjD3zAiLTHX8ud/HqMbljT+JCwbU1GU',
                '0IJrJ0a8ZoL4/DBaLBhFzs+0GBXgo4BVcxl0wHmcVFp6RDWSx0f/frQoIaCWM+3NM2XT17',
                '3tAHAcUhnd5rkSKH8eKt5OtFKe8X7LCbC7Ffi5sOvRl5Jx64XZLlYtcfb5NXQtRvZjEXLf',
                'AcMzhl/AEHlT3FmGQhvNIvX0zvHwt4Qbce4MOfAR9T3fI5ir2XfO6cJoQbg22Inakdic3p',
                'MohCiebrSlWb1+dG+xus4n'
            ].join(''));
        });

        // More detailed tests in auth_request_spec.js
        it('should sign an auth request', function () {
            var auth_request = octokey.authRequest({
                challenge: 'KWm5PMQC3UYSFY/xgLimHvLhLcuIdwRZoDm4UfEADO0=',
                request_url: 'https://www.example.com/login',
                username: 'foo'
            });
            auth_request.sign(private_key);
            expect(auth_request.toBase64()).toBe([
                'AAAAIClpuTzEAt1GEhWP8YC4ph7y4S3LiHcEWaA5uFHxAAztAAAAHWh0dHBzOi8vd3d3Lm',
                'V4YW1wbGUuY29tL2xvZ2luAAAAA2ZvbwAAAAxvY3Rva2V5LWF1dGgAAAAJcHVibGlja2V5',
                'AAAAB3NzaC1yc2EAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCsJAbbXe63OoTlhWNNUX',
                'l7EZEKQT064zssKn8U6492gesVReTLYxBzB/b0ncDiLzPGkRL1F1IRTqIgSyjD3zAiLTHX',
                '8ud/HqMbljT+JCwbU1GU0IJrJ0a8ZoL4/DBaLBhFzs+0GBXgo4BVcxl0wHmcVFp6RDWSx0',
                'f/frQoIaCWM+3NM2XT173tAHAcUhnd5rkSKH8eKt5OtFKe8X7LCbC7Ffi5sOvRl5Jx64XZ',
                'LlYtcfb5NXQtRvZjEXLfAcMzhl/AEHlT3FmGQhvNIvX0zvHwt4Qbce4MOfAR9T3fI5ir2X',
                'fO6cJoQbg22Inakdic3pMohCiebrSlWb1+dG+xus4nAAABDwAAAAdzc2gtcnNhAAABAJiS',
                '/1wbhNKzLIv26kgzXWWQZe8O719m51WmOXclvVsIRnnQm7R+5840ff+RrLu0Gj0zT9uGGl',
                'DQe9zhi33CaPCAkd1mufnCMvy9/D1jkbCSQIydMgvRb+Jni4zanPVBg1edx6cHMiteViei',
                'Dt76mmvNUZ6pq32b2RM6syUNTBOitUclQDZ73Fq7JqLEjY6XtrQcoUYYcOCHsc5yc8rAZ1',
                'YW+ZbqoMLF1BCGu/4UGQddUwjZ6qkpnwaSH1S1HMkjmJSO4jF5Z6O5Co091kxa3ZXgVFxq',
                'nqQ6UTDmsotUMTZBfgNHDuAKaQey2mBU5ykHkrTHoeyZ4vgVMqhrt0KMXvI='
            ].join(''));
        });
    });


    describe('with an encrypted private key', function () {
        var private_key, private_key_pem = [
            '-----BEGIN ENCRYPTED PRIVATE KEY-----',
            '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',
            'OKiDhXJniRaM7Z81WuAWeNeg5QaitrEnlxBY',
            '-----END ENCRYPTED PRIVATE KEY-----'
        ].join('\r\n');

        beforeEach(function () {
            private_key = octokey.privateKey(private_key_pem);
            jasmine.Clock.useMock();
        });

        describe('if no passphrase is given', function () {
            it('should require a passphrase', function () {
                expect(private_key.passphrase_required).toBe(true);
            });
        });

        describe('if the wrong passphrase is given', function () {
            var set_passphrase_returned;
            beforeEach(function () {
                set_passphrase_returned = private_key.setPassphrase('not the passphrase');
            });

            it('should return false from setPassphrase', function () {
                expect(set_passphrase_returned).toBe(false);
            });

            it('should continue to require a passphrase', function () {
                expect(private_key.passphrase_required).toBe(true);
            });
        });

        describe('if the correct passphrase is given', function () {
            var set_passphrase_returned;
            beforeEach(function () {
                set_passphrase_returned = private_key.setPassphrase('password');
            });

            it('should return true from setPassphrase', function () {
                expect(set_passphrase_returned).toBe(true);
            });

            it('should unlock the private key for a few minutes', function () {
                expect(private_key.passphrase_required).toBe(false);
                jasmine.Clock.tick(120000); // 2 minutes
                expect(private_key.passphrase_required).toBe(false);
            });

            it('should extract the public key from the private key', function () {
                expect(private_key.publicKey().toBase64()).toBe([
                    'ssh-rsa ',
                    'AAAAB3NzaC1yc2EAAAADAQABAAABAQC8wjLP42FK43SOaSwTPwsnVXX97WtnSSuIPtN00q',
                    'j62nbaPyrfIOwiWqb4FIrsAoa97uJgYovDZcTkBKTzpwLj1rKpQva3elwxFfQcpz4T3jDX',
                    '+DxODLF36BQSf2QoAsNUTdP12tiDJOgK2Qqp//+6iZUHtgM/csZckDpMv0uzNn+do4LFm7',
                    '0ddqJYuZ3r/lFoGLAfWLGBmVMWEajYZWP8CfN8/+LLtQ3DPQ9rK0jPwWZDKa9tOTaqWryk',
                    '33iv9Ecx1ryHyz1Q0PsgRixlnaRibr3RKYyFtPl0PBgT92hhrngwWVbkTwOmvvjHCof4D+',
                    'rV7dUlck+dm9SsxTh5MF5B'
                ].join(''));
            });

            it('should sign an auth request', function () {
                var auth_request = octokey.authRequest({
                    challenge: 'KWm5PMQC3UYSFY/xgLimHvLhLcuIdwRZoDm4UfEADO0=',
                    request_url: 'https://www.example.com/login',
                    username: 'foo'
                });
                auth_request.sign(private_key);
                expect(auth_request.toBase64()).toBe([
                    'AAAAIClpuTzEAt1GEhWP8YC4ph7y4S3LiHcEWaA5uFHxAAztAAAAHWh0dHBzOi8vd3d3Lm',
                    'V4YW1wbGUuY29tL2xvZ2luAAAAA2ZvbwAAAAxvY3Rva2V5LWF1dGgAAAAJcHVibGlja2V5',
                    'AAAAB3NzaC1yc2EAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQC8wjLP42FK43SOaSwTPw',
                    'snVXX97WtnSSuIPtN00qj62nbaPyrfIOwiWqb4FIrsAoa97uJgYovDZcTkBKTzpwLj1rKp',
                    'Qva3elwxFfQcpz4T3jDX+DxODLF36BQSf2QoAsNUTdP12tiDJOgK2Qqp//+6iZUHtgM/cs',
                    'ZckDpMv0uzNn+do4LFm70ddqJYuZ3r/lFoGLAfWLGBmVMWEajYZWP8CfN8/+LLtQ3DPQ9r',
                    'K0jPwWZDKa9tOTaqWryk33iv9Ecx1ryHyz1Q0PsgRixlnaRibr3RKYyFtPl0PBgT92hhrn',
                    'gwWVbkTwOmvvjHCof4D+rV7dUlck+dm9SsxTh5MF5BAAABDwAAAAdzc2gtcnNhAAABAFKx',
                    'IIgdttaOeSwg18V03/qbMzTaIh3ga/PEfKO06x4Dh3WBACEdaVf5+2mW+UY+xCoF6zkYed',
                    'qBX2DIXjefzqgU+ELi633NILwyHAVWf0OpXrryhuSUC5cBQtnNNZXsd/a/4xZmsQi/+HV/',
                    'XgkFWFSir0qd7itfmbkrBhlQBDXLgagR3kJtDct3bEx2/k6/qnTkje7ZLd0eoY73NF8Xks',
                    'mGqIB0W36jcJlC6TDaFakvdXtO8h9JsAMQmwzjG6+KJM0pFL+uNU+VcU7O/NuT0V0qEeOZ',
                    'GCR2chj4cUIQF5ETKAWa4gOuNUwBbvauUXUrErPxgySMSvdYaNvFC5Yguio='
                ].join(''));
            });
        });

        describe('after the private key unlock has expired', function () {
            beforeEach(function () {
                private_key.setPassphrase('password');
                jasmine.Clock.tick(600000); // 10 minutes
            });

            it('should require a passphrase again', function () {
                expect(private_key.passphrase_required).toBe(true);
            });
        });
    });
});


describe('octokey.privateKey.convert', function () {

    describe('with an unencrypted traditional RSA key', function () {
        var input_pem = [
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

        it('should convert to unencrypted PKCS#8 if no passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem);
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
            expect(forge.pki.pemToDer(converted.pem).toHex()).toMatch(new RegExp(['^',
                '308204bd', // top-level sequence node
                '020100',   // PrivateKeyInfo structure version 0
                '300d06092a864886f70d0101010500', // AlgorithmIdentifier with rsaEncryption OID
                '048204a7', // octet string
                '308204a3', // 9-element sequence containing the RSA parameters
                '020100',   // RSA private key structure version 0
                '0282010100ac2406db5deeb73a84e585634d51797b11910a413d3ae33b2c2a7f' // start of the RSA modulus
            ].join('')));
        });

        it('should convert to encrypted PKCS#8 if a passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'my new passphrase');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
            expect(forge.pki.pemToDer(converted.pem).toHex()).toMatch(new RegExp(['^',
                '308205273051',     // top-level sequence nodes
                '06092a864886f70d01050d', // OID for PBES2 in PKCS#5 version 2.0 (1.2.840.113549.1.5.13)
                '30443023',         // sequence nodes
                '06092a864886f70d01050c', // OID for PBKDF2 in PKCS#5 version 2.0 (1.2.840.113549.1.5.12)
                '3016',             // sequence of salt and iteration count
                '0410[0-9a-f]{32}', // 16 bytes of salt
                '02020800',         // iteration count = 2048
                '301d',             // sequence of cipher identifier and IV
                '0609608648016503040102', // OID for AES-128-CBC (2.16.840.1.101.3.4.1.2)
                '0410[0-9a-f]{32}'  // 16 bytes of IV
            ].join('')));
        });
    });


    describe('with an AES-encrypted traditional RSA key', function () {
        var input_pem = [
            '-----BEGIN RSA PRIVATE KEY-----',
            'Proc-Type: 4,ENCRYPTED',
            'DEK-Info: AES-128-CBC,C20284DFE2574C53BAF2C73072F99995',
            '',
            'BmocszCeDrK1GWwqGEr5jU+VnpdG1mRkdYXQ1EKTWfW35fCLLOl/KZyFe7TF6fuM',
            'NDK8vaCVCFBKKyfcftPga9jwCuZHvENjYPjj7Pds/iAwjYsxx77Jk4Xd1ulaSYlm',
            'idOssZs5DllpG2P+UfVS8XH+Te+4Xw7+1Mx7m9OJA9PKM6H/5jIC+XJuRNMTEt8h',
            'Rie1+8io+BFsk0wnURDcVwRmvBr0VaZuRoOCZB9UmCHS0bXUVDivkFRUr7YZ0vJm',
            'BS8KFzHV8/H8IFvXQvsOczm4iGp7RvYO7mJ27H/ffQFukE44Dh1K5SbBdF4xSadK',
            'Ly7btSyvPCT2QFeJdxcF/9TDJDbUaySxXp67x5eY2OGeS6M67ZxTsFOMI0IOEmkX',
            'isxQXpt29iwyBi0vqmw9Q7yJgT+MRHekTCCozEiW9s9yuKUea1jsJ92bgHaP177J',
            'pQ3JRhtWJBN2faKpsrLGcnKjTGgRZTJR6tkIiNkmd2tmIjB7m5ViKVIJz0Yoz8xf',
            'IxF6kJWMBKnx/VitGxKXUb9y8zrBn9TTn2YE9Ag8YyxjLAs/HkKfmQb0nc43Pf0W',
            'NEhdrmRC9IYI93M/+oZneJjw7ix4PPFLOoNhJ272zALDb8EhkadSSl/fDks3RXmI',
            'XzZVjNlRDROiM49xxYjINSGhBKYR5t6TG/RnvqyVqVpzgQ4X43XBNkMFHdm5tcB1',
            'bRas12EfdpgGmDsYCcj2YulH+0tj56fDw8lmOOrkVYQZO8hmRJYrJPXNPoE53UEN',
            'XjhBvYCsWDBltgZJqWfLLDIJ9Q118332m+oS2W6Q+gMlcdlRzvVpZcruIc6jz0SS',
            'WgJC/vpuKCF+8MDwO8OCGO6Vd+3CJeyJdMFAEaGZi6LLU+FZsaR3yC4ddieop5Mi',
            'ZCUoewWoBlbgD8DB6lhlaz9VwW4nc7yJKVLGWXQxycJpcbjbMf9SscKvyScA7/wF',
            '405Y31u59NRafGrJtsvipd8DYK+al7cWCsBUJU4G9QNnAlOVQBbxUnf7VgbhC1xz',
            'DLZZScLcLIsVPBUzHXPgr5TZLTqjrKFVAGI4C6yMJW7R9r56J4LLgXxAj9Nls93j',
            'CTBZZEoneu6V4tGNNCh8dE9rsXb7Szz9bFZKjhoIbVXEpSbCta0+m0JYsRvMMdMt',
            'bQJtJaJBoY4zaIvI9pweE+3UI7NFXBxG23sZ/NJYnpR/wNoo6Qi1JvWxh+Q1cgoO',
            '+BOBvvhuugCz653K2ETIGqrvWhwSpNGWLfG260+1ia7/cSDljHr6jESRAEaqRqIP',
            'A4ENfGSrzpJJ+6gO08+3lKMwJTGpcbnJxB/dBZzSBZSu86E1/b/Ry9dV9biIhOSU',
            '1HPuXF3ULJJZYzApnTt6AH/vJMncYrV8flB/YfApXoYixaNBKTg0h2K38H5vysti',
            'RPiYIReVWKaSqg7sAJa03SPJx5tbblAmwz4fd4JXmjFpbAuQvSy1cYwfSkjn4Rk4',
            'VVFqtqud9MYzVWLBX1EZ3Nd6nSC9UsVUtza3Wzs5lWgNev/9rzIu99SKPW9nRclM',
            '5eD+BFd+EDtrsjPsjfHFru5B9rJCq9LfKDenghbfTTKoQMYj2y3toNYrcETzMvhv',
            '-----END RSA PRIVATE KEY-----'
        ].join('\r\n');

        it('should convert to unencrypted PKCS#8 if no output passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'password', '');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
            var key = forge.pki.privateKeyFromPem(converted.pem);
            expect(key.e.toString(10)).toBe('65537');
        });

        it('should convert to encrypted PKCS#8 if a passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'password');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
            var key = forge.pki.decryptRsaPrivateKey(converted.pem, 'password');
            expect(key.e.toString(10)).toBe('65537');
        });

        it('should return an error if no passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem);
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('input passphrase required');
        });

        it('should return an error if the wrong passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'not the password');
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('incorrect input passphrase');
        });
    });


    describe('with a 3DES-encrypted traditional RSA key', function () {
        var input_pem = [
            '-----BEGIN RSA PRIVATE KEY-----',
            'Proc-Type: 4,ENCRYPTED',
            'DEK-Info: DES-EDE3-CBC,6A9DD947BF7E78D3',
            '',
            'dWy+96hq8lZR5u+p9Xzbza6Znfd9yLaGKyPgLYpXCZKE6CQg26157bgZDaMb3YiI',
            'wUvwbjunKEED8ZZiZ3AEJgWQ6iNmmYxF2K30HdM/sLzYKXOVCQ46qd6WY5jvFepT',
            'l+G0r7S0pc1Q8xzBkMMOEmYQ9LK/Yz8fUSIhiwnsfwx8I1wE8JveXs8c4F6qTqgq',
            'J1PFbaxj7Q8zvI7DjngOxw75TbnyVuC6CJUMxalgsCgXojfRyG9hULcTCRFpC2t0',
            'EKfTK7ZEjlKNmb9c8XIsL07uzcgZs/DsV/qXlUDJTLMIQormFtoG9SilpxsmFgt0',
            'MxLV7oiFBafQakCzzSMoVgEHRP3vLpptKtl38IoOMYXyYSLAJzPK0a1524kl9cBh',
            'RwNTCggy913ScTdKYC933fpI/ferzp/XFOB94TvWeD+w8s+jSd0GfNf8na/BUffg',
            '6/IZdvfL/LeVpxtm6CgDFTHPeQPj97GuBCYJQELqmuW0unPPeiifKiec1BVWbySy',
            '7eknhzQZve4UI+Lpmb3CLsq8xNI70iomL2x40GU0LHTf4UCRORmPBK2qgaeKL3p5',
            'iDHkUFdEIcaUWV5p5zpuBI7nbGzWeMVspS8H+X8j5nMudDPb8RkvGAK5nECcbWoJ',
            '9qeITbRcT+o6HczMRbFvyGbcpdeeV74a/KVB4D3X1bC7dpnGCq06z9lcdghvhhh7',
            'rg6Ar6s6UXb9NbxDA2WlhffZaPkfcUi6A9k8/y58xWb6Db6IIMl1nN1ESlfkeDrl',
            'bRrc/UHcBLwusFl54my8y+UxUDL5nb5xq6AXs+3Glb31Tn0GvaZsmWYig0/R4bxs',
            'eJi3BqD57p+QDcv3tBmoDhHdPkvMra7CfoDqLMnTNXKs6jyP5Us6TpNaieEc/pb/',
            '4bdrVTsHhrERbGQWFl4cr+8f34WM4PXOtC/Nax5+8YvuXdIcBhGOEt+yNG+rVBh2',
            'SfIBaD/jOmbKAtOGgNB1ydLcuMZf/8kdNK9s1Jn8l8bM6z0BmlXRl7GghnjRD34c',
            'zWVEGMI2+wnnkgidSw2h89dduShdf3TYUjiAI/fwJLvHcG/u8fZC/ItrHRqw9+dX',
            'QVH7++NyLJSb6vI/eIme8fPBBb69WcoSWLbw2t/89YGVpzdI4+wRTjy9ZzFWuRf8',
            'ciXv/nLa0t0fOHE6wSb576/5zw46XLaFfaadk3RrgMb6OajMva4D8UbMxJQwL6Pg',
            'B35pCy1KxWXm6rCs4A/P7idp3JW2ok4+U4cQwS1rB7NS8zN+mStpcHstn8NE2icd',
            'APMkT/I08MN5atIDa5ZlETIhnzQKk2WvTa1fHOtX6ydxTyOwXtnToVtWeiJjToVy',
            'zIQDSEyV5uw4THm+XGF4zCFLVVmH+3zdlGIJdtEXxCK65adbmqhcMupdwZ70h3At',
            'zlUQzlkhBtRvvI2nIiL6A33yLAMj8k9Mno0mHiRzPmKeIpsZh5s4FXwBxsX3Iw0r',
            'SijPzvxC39CZwoA6n0l44VdGyyYA85YX7C8jl1x2h727ARy+YHPSvKXNIvFuXn0y',
            'T8iwMHBhGhFIlp8rglmMEV0pIcsD72EKf3LpksE0MokHItVI15sYauai/E+jH0iz',
            '-----END RSA PRIVATE KEY-----'
        ].join('\n');

        var modulus = [
            'd46d9b87230533489282d90d12228fd9da5f68eab6eab57b48a1588b9e05cd01',
            'cd0ab29f14f871c69bdc2ce73c89bdc82ebca958bc30fea7dbf5ed1bd3dc72a8',
            '20f786757d9d616c86b36b5e20c19a4a5fddf8b4709bc059f93e71b7ef5f57a7',
            '815ffcee7287ccd1a8996719fae1fbf9c20b999b1c668de26b6eac8463dfea05',
            'ef77d8f2b3b511fb60e6930934ed00ee33afb1ade032dae641f5d029683e92a5',
            'eb2ef599daf1aeb885bfe6a24112deb8043e4a14f82327cdda038534a7bfd141',
            'e5ee81f3bdd94c34695352867e0f49c3c93a4f1037935a69d1920f772b66494d',
            'ede7eab3639e8eeef500a983c6508189650c64754432718bb7c820a0e6df646d'
        ].join('');

        it('should convert to unencrypted PKCS#8 if no output passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'password', '');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
            var key = forge.pki.privateKeyFromPem(converted.pem);
            expect(key.e.toString(16)).toBe('23');
            expect(key.n.toString(16)).toBe(modulus);
        });

        it('should convert to encrypted PKCS#8 if a passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'password');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
            var key = forge.pki.decryptRsaPrivateKey(converted.pem, 'password');
            expect(key.e.toString(16)).toBe('23');
            expect(key.n.toString(16)).toBe(modulus);
        });

        it('should return an error if no passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem);
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('input passphrase required');
        });

        it('should return an error if the wrong passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'not the password');
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('incorrect input passphrase');
        });
    });


    describe('with an AES-encrypted PKCS#8 RSA key', function () {
        var input_pem = [
            '-----BEGIN ENCRYPTED PRIVATE KEY-----',
            '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',
            'UFvqwsIRhT9t1uk8yPnsuQMPlf5iKzMAwcl2',
            '-----END ENCRYPTED PRIVATE KEY----- '
        ].join('\r\n');

        var modulus = [
            'bcc232cfe3614ae3748e692c133f0b275575fded6b67492b883ed374d2a8fada',
            '76da3f2adf20ec225aa6f8148aec0286bdeee260628bc365c4e404a4f3a702e3',
            'd6b2a942f6b77a5c3115f41ca73e13de30d7f83c4e0cb177e814127f642802c3',
            '544dd3f5dad88324e80ad90aa9ffffba899507b6033f72c65c903a4cbf4bb336',
            '7f9da382c59bbd1d76a258b99debfe516818b01f58b18199531611a8d86563fc',
            '09f37cffe2cbb50dc33d0f6b2b48cfc1664329af6d3936aa5abca4df78aff447',
            '31d6bc87cb3d50d0fb20462c659da4626ebdd1298c85b4f9743c1813f76861ae',
            '78305956e44f03a6bef8c70a87f80fead5edd525724f9d9bd4acc53879305e41'
        ].join('');

        it('should convert to unencrypted PKCS#8 if no output passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'password', '');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
            var key = forge.pki.privateKeyFromPem(converted.pem);
            expect(key.e.toString(16)).toBe('10001');
            expect(key.n.toString(16)).toBe(modulus);
        });

        it('should convert to encrypted PKCS#8 if the same passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'password');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
            var key = forge.pki.decryptRsaPrivateKey(converted.pem, 'password');
            expect(key.e.toString(16)).toBe('10001');
            expect(key.n.toString(16)).toBe(modulus);
        });

        it('should re-encrypt in PKCS#8 if a different passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'password', 'new better passphrase');
            expect(converted.errors).toBeNull();
            expect(converted.pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
            var key = forge.pki.decryptRsaPrivateKey(converted.pem, 'new better passphrase');
            expect(key.e.toString(16)).toBe('10001');
            expect(key.n.toString(16)).toBe(modulus);
        });

        it('should return an error if no passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem);
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('input passphrase required');
        });

        it('should return an error if the wrong passphrase is given', function () {
            var converted = octokey.privateKey.convert(input_pem, 'not the password');
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('incorrect input passphrase');
        });
    });


    // TODO encodings in this section might be worth supporting. They are tested for failure here so
    // make sure our error handling is sane in case the user gives a key in one of these encodings.
    // If you add support for it, you're welcome to test for success instead of failure :)
    describe('with an obscure key encoding', function () {
        it('should reject a PBE1 DES-encrypted RSA key', function () {
            var input_pem = [
                '-----BEGIN ENCRYPTED PRIVATE KEY-----',
                'MIIE6TAbBgkqhkiG9w0BBQMwDgQITQQKgSWQnWkCAggABIIEyLnYZK/8hkLpiWDo',
                'nFINuywF6pC6R/0ewbJ0Fq/uB7Gpa+TyxLjPZ8PIS9pnP3+HE6kKO3nVSwSlZO0L',
                'RV7qPkMcIL2djh0jcKFRwu8o8ikAgyt/xyJIaHk3dRmfK8apRmAH4JgyBdrStDqp',
                'L6ME6oXyjG3nAg9q3P5J1hkQdOyzXn9KTzTpOpxuzRAdUJiOrV63E5tVxa/0hsVy',
                'mXwlDUE2x6hHgKJP1uHDVrauq3MFAC7wTpyziVRY4CeSbvSpI+diA3ypX7zUhMag',
                'Ek8K3pvhSl5Rin6VWKTzy5HTcyz/Nn7ppsZw7ysxUKkhylZe2rI/PiKLoLH3JwNb',
                'LoYAAggOAQLUFUpJMrxNRPyUuIr6FzL3YiPE4ZWi+yVsHETwfUo8zAzgArTVddEE',
                '4Oc1ngqVw78nXYZgEOTqekepTKboa5wEkBCtftUPW+aHbteGMTAPMFq4PEZyzn8d',
                'YC3rRUpA4renltXlZVKArPv2lvrkmQbfEYxsZypJw/a+tYUwNj4gjlm8ugWbPMci',
                'Eo8TPg3TDYKt1uHq81cDXkZgOxuMsP2si7KXwXJOfVlbOOlfQjEV2tv24jJ5piVN',
                '5wPO2Gv5kDZtx4Kxoy4Toejsl0s0GQcbm1cbJqG9g3Xb6nVLZ0sagTIJldStIsEY',
                'vTGwSnPON24jAbUap5QDrAMEGTrBimzAhqfuoZz8qV/PbiTD5yZZhPTqsxcOD0wR',
                'OxUPIWy/S9KUBmawkqGg7YGre/G5J7UE3iR4+Pw9xYfemEanlQoKiBy5YIioVBjC',
                'btqgqHPHNxcK3LNnCBwXbhLs1O0MoG58JNnWGbqK6mm1H/kQWJD7Cl+HMZ+Ycrc+',
                'xhTtFSzr6AkFYKZOoAFoFohvvDA4/UbqIj+wSKRRjqGsoJ1jtoSb/jEN2bZePpgR',
                'ZAFl9JnOLjc0stenaPHeqLm7+5z3/hem1V3vSuRUdJDZn343uUhGBwOp6gafou7w',
                'rpZAYauUh7Uqxf3L5ufwawJT1L/K7hnTHytWU0q7X6rhnANscZDxyR4CrLoBFtyF',
                'LHocwyVmHnFSLRpI4V573OAfwB06CL/527KQnloKMkUKgwUzJ/t/cEH2OhFQqavJ',
                'N4gSz7KonwXIvGpGugQVfReorqarPTNUhFW2cPw2ChXjgn1f49Mbnz//AgRVt0vz',
                'jws5Db1m8FqcuYWyIdsvDMS5l3ddlVSW6wPoaBd52+X1Y1nuNRCuNBYHy//Hx5gY',
                'issopZeVY38kQ2T8vbCMuSFTXtXFHLwBp3qmWcRlYU5lJjZllT33YtvR0U2X1epK',
                '/lGOR/1SiUKSg7oY8dl3pqhSaGZArwZC2eBNj70V58wDsYa3hU5wfu1A6FG4A9G/',
                'rLnS0ahR2/b7PUbSuZX1+qalFgPynb7ivpyPo4KOrn7I2i62xCEkwHjv6eJl/8Eq',
                'XNcmLLqxtbmtI9VimzVTHxD3pFRBP0fBEEMrAzgWxkgrKpyqAqnmT8aPnB773ROd',
                'LauWSG5UdSOI7SbTiNfHqqh36i5+KgzECzFCW1nWM+wb6mZZz2P/ZOcfiaG6P8ZU',
                'NHtmEHxeQv5e6qlrYoTBqmax70rHnMO5/uMpaWqDPhTpMpKZ99DtBoFzRyTcCvfL',
                '0lXYU8b18LJtYQgrNg==',
                '-----END ENCRYPTED PRIVATE KEY-----'
            ].join('\n');
            var converted = octokey.privateKey.convert(input_pem, 'password');
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('Cannot read encrypted private key. Unsupported OID.');
        });

        it('should reject a PBE2 3DES-encrypted RSA key', function () {
            var input_pem = [
                '-----BEGIN ENCRYPTED PRIVATE KEY-----',
                'MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIyvAhIqcNwHMCAggA',
                'MBQGCCqGSIb3DQMHBAgLQtFdlc5NZwSCBMjN5CUiiNQrCQnEdKh8A13EvyO/EmNs',
                '4YrVRdikOzO/1JAoIfRMcX7EppYEsE96X1CXuImetWkRz8qlOw0rsh0jgi3/Jf3d',
                'gReNwrZYkjzAqGzmSYXOvxCkUqWKR2zXs3opHIeKrdL0RMfBxsGc5HVsD+CeF2Vu',
                'CMj0umqOJXrxEMO6zblRSemeYDWy0s5L2c0yReuRxoybOEGvNoPZ/LE1YF8ENt6y',
                'BcNyk4HlvTbq2TRuyg8eLIFs7Pd1unLvonPbM3S0G8ZH2gnrRpz3OQFHlS5F8u/A',
                'pxZW37NHPoUsKDRevlVLF3L+3pqx0Kgbqz1TcwwUafUb1UJf8v6q0iJqZdwxIDo6',
                'XdptCObojoa6jo320wFtkGB9etrWhe3M8j23B8gr0dYi8mrDPr+VbC5njhNwDjxN',
                'PqY3FpumZIpRDtITVE1OBh7lxZFsIA9W6f7ckSRKquWc4q+mlcYYy+4rdHVD+IfI',
                'X6l3xbo6A29KuVN4Dl/xQsmmAJv2DvchbE5dZ7ZO5Y73d0W09OxM3pcEfgDjJDw5',
                'EX4bJwGGhb3e4Cs8drcBglAIrosMO5CnuYtQVoQWd2Aa9kiyhKnrQi9qaRoPbl3H',
                'SGqBpitEncYXqkz3K+BStKXjb+ZxfDFBsZCDWaV2L/2BRYLd7SLSrjVczmXKUASh',
                '+Y8iFFvQ2bfBMN3+4FRMkxQzRL7NewmoBMnKA74muZ1VOrP8370w1AiRchF91vLj',
                'xcYlNRwNTQcL1JMcodYZq7LE9SHejO0FzoGE42Bd/xZmJ8fTprVxrE3fSWmyenjz',
                'ESWwcOf1jwJUmwEyzuc5uhGsjDGOT2bqbZm2xnEGoif1zGRjNj7qf4TJtQljQ6GK',
                '992jTEr69KvLlTJdzBZc+mC8231ni+7KEVbhVDIjtUouqFa2CtzOwJy/DlMVZItP',
                '3B0zT+Voz675qzJFEFHFggUVaFXVsQOyJWH438o0uab5UIhL9yLpPshG/bV4wN5G',
                'siYxJp9aAIcf7d6YJ/emO6QUluQvq6bGOFmstlTVlizvCo57BiBbj7t4ZiKXjyxw',
                'g6xQkzfgWe3t+cqy444FFZoduvnBNgV3xMKjRKBWDKfaP6HZZcGrywRgc2D4pVLF',
                'PaC3nZBIlBW+ILiAFP/RivV+eUPaS6s28GuBfXqfuKSM9/KY4xtiU1N/QaUMpwMH',
                '+0wdiHQQkMnwqNSoQbk4U0S70hgDdUYkkjIlpkVmIBDFpbz99bsX5YvMhMw1pdON',
                'BihPtaG7HYlGNU1jnw7hvivsSPLUl6ijNZ91e4h07ajP7RdbYfw3IIkf0ymWnSW1',
                '6684o5irLUPwsb+kH+Gt3V9Mq0Ui0WIMD6wkAXF3OqKyVaPqUacwxZU3sYnYmfuV',
                'TMrPENKhiilgYB23Rwb5F16gmnRSpVv4x8zJRv5XpR5eO+dhllUfeCMAtEKvUiw3',
                'RKF/t++8c53VXOV5YyOGnYCheycE+qNwGcLHIf6GASCWs4a2A6u2HhSA70joHqB+',
                'xCd6oJfzK2R+jMhPbmDXlaivkutod3/WEzzB5GghaWtE5W6b5y7bAxkzXQ3EDN3h',
                'FEXuABK/jLtWdJhpxWEB6ifoqlai07ywrFrFe9PjJf+hpR5nFKDF5aYdKBerHVF6',
                '/dk=',
                '-----END ENCRYPTED PRIVATE KEY-----'
            ].join('\n');
            var converted = octokey.privateKey.convert(input_pem, 'password');
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('Cannot read encrypted private key. Unsupported encryption scheme OID.');
        });
    });


    describe('with an unsupported key type', function () {
        it('should reject a truncated PEM file', function () {
            var input_pem = [ // last 3 lines missing, simulating a copy & paste error
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
                'qVEzAoGADfMjOQ5OjbflVAfr6Lnnf/OoO5bx9L4/3wtjCblIzSTHYP02CyEZttz5'
            ].join('\n');
            var converted = octokey.privateKey.convert(input_pem);
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('the RSA private key file has an invalid structure');
        });

        it('should reject a corrupted PEM file', function () {
            var input_pem = [ // I changed the first character in this string
                '-----BEGIN RSA PRIVATE KEY-----',
                'Proc-Type: 4,ENCRYPTED',
                'DEK-Info: AES-128-CBC,C20284DFE2574C53BAF2C73072F99995',
                '',
                'bmocszCeDrK1GWwqGEr5jU+VnpdG1mRkdYXQ1EKTWfW35fCLLOl/KZyFe7TF6fuM',
                'NDK8vaCVCFBKKyfcftPga9jwCuZHvENjYPjj7Pds/iAwjYsxx77Jk4Xd1ulaSYlm',
                'idOssZs5DllpG2P+UfVS8XH+Te+4Xw7+1Mx7m9OJA9PKM6H/5jIC+XJuRNMTEt8h',
                'Rie1+8io+BFsk0wnURDcVwRmvBr0VaZuRoOCZB9UmCHS0bXUVDivkFRUr7YZ0vJm',
                'BS8KFzHV8/H8IFvXQvsOczm4iGp7RvYO7mJ27H/ffQFukE44Dh1K5SbBdF4xSadK',
                'Ly7btSyvPCT2QFeJdxcF/9TDJDbUaySxXp67x5eY2OGeS6M67ZxTsFOMI0IOEmkX',
                'isxQXpt29iwyBi0vqmw9Q7yJgT+MRHekTCCozEiW9s9yuKUea1jsJ92bgHaP177J',
                'pQ3JRhtWJBN2faKpsrLGcnKjTGgRZTJR6tkIiNkmd2tmIjB7m5ViKVIJz0Yoz8xf',
                'IxF6kJWMBKnx/VitGxKXUb9y8zrBn9TTn2YE9Ag8YyxjLAs/HkKfmQb0nc43Pf0W',
                'NEhdrmRC9IYI93M/+oZneJjw7ix4PPFLOoNhJ272zALDb8EhkadSSl/fDks3RXmI',
                'XzZVjNlRDROiM49xxYjINSGhBKYR5t6TG/RnvqyVqVpzgQ4X43XBNkMFHdm5tcB1',
                'bRas12EfdpgGmDsYCcj2YulH+0tj56fDw8lmOOrkVYQZO8hmRJYrJPXNPoE53UEN',
                'XjhBvYCsWDBltgZJqWfLLDIJ9Q118332m+oS2W6Q+gMlcdlRzvVpZcruIc6jz0SS',
                'WgJC/vpuKCF+8MDwO8OCGO6Vd+3CJeyJdMFAEaGZi6LLU+FZsaR3yC4ddieop5Mi',
                'ZCUoewWoBlbgD8DB6lhlaz9VwW4nc7yJKVLGWXQxycJpcbjbMf9SscKvyScA7/wF',
                '405Y31u59NRafGrJtsvipd8DYK+al7cWCsBUJU4G9QNnAlOVQBbxUnf7VgbhC1xz',
                'DLZZScLcLIsVPBUzHXPgr5TZLTqjrKFVAGI4C6yMJW7R9r56J4LLgXxAj9Nls93j',
                'CTBZZEoneu6V4tGNNCh8dE9rsXb7Szz9bFZKjhoIbVXEpSbCta0+m0JYsRvMMdMt',
                'bQJtJaJBoY4zaIvI9pweE+3UI7NFXBxG23sZ/NJYnpR/wNoo6Qi1JvWxh+Q1cgoO',
                '+BOBvvhuugCz653K2ETIGqrvWhwSpNGWLfG260+1ia7/cSDljHr6jESRAEaqRqIP',
                'A4ENfGSrzpJJ+6gO08+3lKMwJTGpcbnJxB/dBZzSBZSu86E1/b/Ry9dV9biIhOSU',
                '1HPuXF3ULJJZYzApnTt6AH/vJMncYrV8flB/YfApXoYixaNBKTg0h2K38H5vysti',
                'RPiYIReVWKaSqg7sAJa03SPJx5tbblAmwz4fd4JXmjFpbAuQvSy1cYwfSkjn4Rk4',
                'VVFqtqud9MYzVWLBX1EZ3Nd6nSC9UsVUtza3Wzs5lWgNev/9rzIu99SKPW9nRclM',
                '5eD+BFd+EDtrsjPsjfHFru5B9rJCq9LfKDenghbfTTKoQMYj2y3toNYrcETzMvhv',
                '-----END RSA PRIVATE KEY-----'
            ].join('\n');
            var converted = octokey.privateKey.convert(input_pem, 'password');
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('incorrect input passphrase'); // can't tell the difference :(
        });

        it('should reject an unencrypted traditional DSA key', function () {
            var input_pem = [
                '-----BEGIN DSA PRIVATE KEY-----',
                'MIIBugIBAAKBgQDVKSUqVuO/gEzML7xwjhdP6en6OiRqD329HipJs7T+QlDKpf4k',
                '5YyRSR3F4Jv+i+mxYNdhrtTvEP+/fLr2+vuScoB4vYQAbu+ukIjvMpSHb+xU/pbu',
                'EdCqMGa7jq4wzHhL3uFk5nsunZ8q6NLxg4if3GoHud+9sd9fgZcQmSL1XwIVAMG9',
                'xF9+Lcqom6ZFuoeJv7/8HSDlAoGAVJmPgN9UiEaI8pmHIudqwufA506DNaTDwyMy',
                'oQ4RBjCzAh9OFQ6BnUmKGNkzXEmbWnuXgBL7wuW7E5cX3FIz80zdxfiWkeSZ1eNp',
                'oK2GoLQk3OyMamXah8mZWRr0xZlGdCBcE3brGiA6nmfZqe4VZVAB2lwesruXEydu',
                'hx7j8PYCgYAwoUeWTdT95mYUnJQ39YUZ4ZOIs4f4PKelNcZgOeO4mUO/sSi9Yp+w',
                'epwY+O1l7dYr2BchVy31OnXwZbTe7zsKavodOs0uP6GtkkO/00BlkG8bVjsgE2BM',
                'AmjhEmcUYKn0q7JBGp5vhMeAL5mnEDDho2plvqofzuwKm2o5DWXyWAIUQL78qCgx',
                'n8cVFqWqMgp7bxLPoec=',
                '-----END DSA PRIVATE KEY-----'
            ].join('\n');
            var converted = octokey.privateKey.convert(input_pem);
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('DSA private keys are not supported');
        });

        it('should reject an encrypted traditional DSA key', function () {
            var input_pem = [
                '-----BEGIN DSA PRIVATE KEY-----',
                'Proc-Type: 4,ENCRYPTED',
                'DEK-Info: AES-128-CBC,6C3F67E991F6002818A7232048802D4A',
                '',
                'l1JHgTEs+qRtwqR/FTxCeH87d/X9lCxw8i8L5pMQwnChr2zSux/1UP+y1VGuWRPr',
                'Dou2GxnElla81FC93xUupFn8gqp1hMXzhnOEHBP6+wUUswFW1GncuXIpdww5R+o7',
                'SiWfWjHRw6pHuJ9eBK/DssljVN8IzWpMk5yktRymC4UAflZ/nBYc99qI8mBe8ZV0',
                'hxZ89urMH309TDV7fhBJGKmITbrJrZo6hRmysEClXzrJWJI2BJ8lAZ4WezLZNu82',
                'irYmeDIxKpiGuPOjaW7ecAP00Ms89kei7Tk4L22xiji48c085Xh4yr/lMaIfFIXE',
                'bIPGy3LpowYtX/czxu8YYpmeGt6mLdH4VOC3SHIphybWliN6PgT19l2DPMV1+Kro',
                'rdkWaMa8GXAvFnu2hCnLRALeDlGxz8pFGPzusZ6oUUYMKJDpNNbZtd6ADJ8Nkp1N',
                'ExvPIuDbRrRK5+ZzZ7fWMUxmbpIXZPmeAQxf91wg2emUZKfLNL2wpGGqcPMAZUev',
                'iszHQf7YnQktXqKIV77zpiCfgiDjL3hvvHeBc6RJ1OmSM6uUxKlChUN4F5Z6wSA5',
                '35176vkLKwSlD0I0ceTX/Q==',
                '-----END DSA PRIVATE KEY-----'
            ].join('\n');
            var converted = octokey.privateKey.convert(input_pem, 'password');
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('DSA private keys are not supported');
        });

        it('should reject an unencrypted PKCS#8-encoded DSA key', function () {
            var input_pem = [
                '-----BEGIN PRIVATE KEY-----',
                'MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBANwjgJrL28LohOt/SPrmDB+lYtt0',
                'FjqMbrFppvA1xAsrNRIA78fE8pMYdKpr/+f6CLpELC8fqJfH5mLcPr6occAnbnXd',
                'hvqzYW3eUWJb1yDrP9D/rAG0r3KQxjXYrVTVUrGcvLWgtnXlGp66c3ikVlfTRByH',
                'wpSYWoJXNN+4Ah2HAhUA/6XELRMItFHgGRaedtcJDwnSrfUCgYEArj9TvhMmOCvr',
                'HupJ4N5qQbpdTZRJ0NxgXXWNxzfnK/QjcRJGarQ3Mdb4DFcHexdihFP1zUWIEdPx',
                '4sU3X8ofpCpyMM6dQWD0QtDU5Zk7ZcJzu086bQ57vdkIRxDY+YdIAZCla5w8r1uC',
                'sfcdIKHDB2JZoQgH70rcSYvdstjk+Q0EFgIUDhbS9IhVyGZ7u4grOp4kec435ew=',
                '-----END PRIVATE KEY-----'
            ].join('\n');
            var converted = octokey.privateKey.convert(input_pem);
            expect(converted.pem).toBeNull();
            expect(converted.errors).toContain('Cannot read private key. ASN.1 object is not an RSAPrivateKey.');
        });
    });
});
