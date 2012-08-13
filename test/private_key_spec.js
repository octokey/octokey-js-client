describe('octokey.privateKey', function () {

    describe('with an unencrypted SSH private key', function () {
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

        // TODO more granular tests
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


    describe('with an AES-encrypted SSH private key', function () {
        var private_key, private_key_pem = [
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
        ].join('\n');

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


    describe('with a 3DES-encrypted SSH private key', function () {
        var private_key, private_key_pem = [
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

        beforeEach(function () {
            private_key = octokey.privateKey(private_key_pem);
            private_key.setPassphrase('password');
        });

        it('should extract the public key from the private key', function () {
            expect(private_key.publicKey().toBase64()).toBe([
                'ssh-rsa ',
                'AAAAB3NzaC1yc2EAAAABIwAAAQEA1G2bhyMFM0iSgtkNEiKP2dpfaOq26rV7SKFYi54FzQ',
                'HNCrKfFPhxxpvcLOc8ib3ILrypWLww/qfb9e0b09xyqCD3hnV9nWFshrNrXiDBmkpf3fi0',
                'cJvAWfk+cbfvX1engV/87nKHzNGomWcZ+uH7+cILmZscZo3ia26shGPf6gXvd9jys7UR+2',
                'Dmkwk07QDuM6+xreAy2uZB9dApaD6Spesu9Zna8a64hb/mokES3rgEPkoU+CMnzdoDhTSn',
                'v9FB5e6B873ZTDRpU1KGfg9Jw8k6TxA3k1pp0ZIPdytmSU3t5+qzY56O7vUAqYPGUIGJZQ',
                'xkdUQycYu3yCCg5t9kbQ=='
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
                'AAAAB3NzaC1yc2EAAAEVAAAAB3NzaC1yc2EAAAABIwAAAQEA1G2bhyMFM0iSgtkNEiKP2d',
                'pfaOq26rV7SKFYi54FzQHNCrKfFPhxxpvcLOc8ib3ILrypWLww/qfb9e0b09xyqCD3hnV9',
                'nWFshrNrXiDBmkpf3fi0cJvAWfk+cbfvX1engV/87nKHzNGomWcZ+uH7+cILmZscZo3ia2',
                '6shGPf6gXvd9jys7UR+2Dmkwk07QDuM6+xreAy2uZB9dApaD6Spesu9Zna8a64hb/mokES',
                '3rgEPkoU+CMnzdoDhTSnv9FB5e6B873ZTDRpU1KGfg9Jw8k6TxA3k1pp0ZIPdytmSU3t5+',
                'qzY56O7vUAqYPGUIGJZQxkdUQycYu3yCCg5t9kbQAAAQ8AAAAHc3NoLXJzYQAAAQCcCiVU',
                'yZj6+MpeGmTCKNhK+2tPfXw6eIBNJA4PlXiheW2c62FPEeIdyYbdlBskdflMKb41yHNee7',
                'wcUzsjCwl2DH4rWdho80WD9yFSMygUn8j/L3p/MLZEwGwiWpyU6ZIkTvF5gciwXAkTupcK',
                '0m2Tm/obo8gR6mwkAaovtaChp2qQOPMYmwCpdW3wtZqx733KJs+Nhg85TWlRHoGCxp+L/A',
                'x5oD3JZUTXVwy9B5Ihqe4+Lv8N19tsI+F9nuWmCCE+lsNpfAOf8WMn39DFnOJDeMRc2sXR',
                'EW/SkckcWgzwNSwx0JniWWQfjDD1EfRZGTN8Q8J7Rg3Pr1kN666W72kz'
            ].join(''));
        });
    });
});
