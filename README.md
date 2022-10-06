# vanityssh-go
vanityssh allows you to generate millions of ED25519 private keys in the OpenSSH private key format and run a regex search against the resulting public keys. You can use this to find patterns in ssh public keys that you like.

## Is it safe to use?
¯\\\_(ツ)\_/¯

This is literally my first golang app and I have no idea if I am generating the keys in a safe way, so trust that however you want.

## Is it malware?
If you set streaming or a sufficiently hard(or impossible) pattern, you will use 100% CPU on all available threads until you manually exit the app.

## Usage

Using vanityssh with no switches results in it returning the first generated ssh key and write it to id_ed25519 and id_ed25519.pub in the current directory.

```bash
Usage of ./vanityssh:
  -insensitive
        case-insensitive
  -regex string
        regex pattern goes here
  -streaming
        Keep processing keys, even after a match
```

## Examples

Regex search, return the first key that matches any of the following consitions:
  1. Case-insensitive "vanity" at the end of the public key
  1. Case-insensitive "1234" at the end of the public key
  1. Case-sensitive "yay" at the end of the public key

```bash
$ ./vanityssh --regex '(?i)vanity$|1234$|(?-i)yay$'
global_user_input = (?i)vanity$|1234$|(?-i)yay$
Regex Pattern =  (?i)vanity$|1234$|(?-i)yay$
Press Ctrl+C to end
SSH Keys Processed = 838634
Total execution time 13.507595831s
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDNDeibTmOGsps2uMnGnATFIA220rGlvaAaTnUoMnsmsgAA
AIj5TWM/+U1jPwAAAAtzc2gtZWQyNTUxOQAAACDNDeibTmOGsps2uMnGnATFIA22
0rGlvaAaTnUoMnsmsgAAAEA5u4xE+2JgExgvE0auyx9c4uHLwDca5c5t4Jw3cqNj
GM0N6JtOY4aymza4aaaaBMUgDbbSsaW9oBpOdSgyeyayAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM0N6JtOY4aymza4aaaaBMUgDbbSsaW9oBpOdSgyeyay
```

Find a public key with the word foobar (case-insensitive) anywhere in it, and keep finding keys forever:
```bash
$ ./vanityssh --streaming --insensitive --regex foobar
global_user_input = foobar
Regex Pattern =  (?i)foobar
Press Ctrl+C to end
SSH Keys Processed = 19836091
Total execution time 5m3.547881075s
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACC5wtZF8fC9UVuUaENRuND8336Dm2kcgCz6aXdrAr3m7AAA
AIijajSyo2o0sgAAAAtzc2gtAAAyNTUxOQAAACC5wtZF8fC9UVuUaENRuND8336D
m2kcgCz6aXdrAr3m7AAAAEBR5YgwA+F6mbfskfPDAzyjlCpXZdI2Df7YsMw2gDZQ
a7nC1kXx8L1RW5RoQ1G4aaaafoObaRyALPppd2sCvebsAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILnC1kXx8L1RW5RoQ1G4aaaafoObaRyALPppd2sCvebs
SSH Keys Processed = 27980128
Total execution time 7m8.214108871s
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDmt8vcX6DgWkUak4D67PaVlASojh8PxGKvZX9Q0qL6IAAA
AIgO97dqDve3agAAAAtzc2gtZWQyNTAAAAAAACDmt8vcX6DgWkUak4D67PaVlASo
jh8PxGKvZX9Q0qL6IAAAAEAVNWLWKspejduNdkMkipu/JgJVKTcgIYIazKCSWtUs
t+aaaaafoOBaRRqTgPrs9pWUBKiOHw/EYq9lf1DSovogAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaaaafoOBaRRqTgPrs9pWUBKiOHw/EYq9lf1DSovog

```

Find a public key whose SHA256 fingerprint starts with `0000`:
```bash
$ ./vanityssh --fingerprint --regex '^0000'
global_user_input = ^0000
Press Ctrl+C to end
SSH Keys Processed = 7420830
Total execution time 46.479848625s
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACCDaz0XpXwr1lXkMe9d/XiYhEqoEo7xND+WfIi6Rcpc9QAA
AIiSMeGukjHhrgAAAAtzc2gtZWQyNTUxOQAAACCDaz0XpXwr1lXkMe9d/XiYhEqo
Eo7xND+WfIi6Rcpc9QAAAEA2q7FROiORV1NCMmOFKpPuJC4PpkiqL8zOJKRjowbZ
34NrPRelfCvWVeQx7139eJiESqgSjvE0P5Z8iLpFylz1AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIINrPRelfCvWVeQx7139eJiESqgSjvE0P5Z8iLpFylz1
SHA256:0000+RLM8XK4vFSKhEUKyvztCIFtR+Q7j04eKB3fA2c=

```
