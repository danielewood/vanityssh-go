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
  -fingerprint
        Match against fingerprint instead of public key
  -insensitive
        case-insensitive
  -json
        json output
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
$ ./vanityssh-go --regex '(?i)vanity$|1234$|(?-i)yay$'
global_user_input = (?i)vanity$|1234$|(?-i)yay$
Press Ctrl+C to end
SSH Keys Processed = 185370
Total execution time 1.149458791s
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACCrwFZ9WG8P8ofh20GZjWUC9wZ5buY+OGh6xCNIRRcmsgAA
AIhrYfv6a2H7+gAAAAtzc2gtZWQyNTUxOQAAACCrwFZ9WG8P8ofh20GZjWUC9wZ5
buY+OGh6xCNIRRcmsgAAAEByY0nqt6jy5matLabyD0JD8KuPgdFiCITXcTQl25AW
RqvAVn1Ybw/yh+HbQZmNZQL3Bnlu5j44aHrEI0hFFyayAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKvAVn1Ybw/yh+HbQZmNZQL3Bnlu5j44aHrEI0hFFyay
SHA256:pDJpPcY7l5opxJl5YwDVD8zMtVlRUWzVDxTb9eOv1q0=

```

Find a public key with the word foobar (case-insensitive) anywhere in it, and keep finding keys forever:

```bash
$ ./vanityssh-go --streaming --insensitive --regex 'foobar'
global_user_input = foobar
Press Ctrl+C to end
SSH Keys Processed = 9466922
Total execution time 52.681194042s
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACCrveor0If4dJQD0dKVY+5IUBTjmwK21zA4k960/0lf7QAA
AIh8UUQyfFFEMgAAAAtzc2gtZWQyNTUxOQAAACCrveor0If4dJQD0dKVY+5IUBTj
mwK21zA4k960/0lf7QAAAEBuxFUgL5j50RFUq+G77wwHxyxT64WHSdF8HQeF14Nk
Kqu96ivQh/h0lAPR0pVj7khQFOObArbXMDiT3rT/SV/tAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKu96ivQh/h0lAPR0pVj7khQFOObArbXMDiT3rT/SV/t
SHA256:oNp2A3nkMlpxP/JuWN/LIjr7Uub7OgqRazrdRJYP8nQ=
SSH Keys Processed = 43275976
Total execution time 4m3.345915375s
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACApQzfSHDQlKjwdn6KGwEbFDn3ExHcmhVDsp+LCMOvSYAAA
AIhsu6hUbLuoVAAAAAtzc2gtZWQyNTUxOQAAACApQzfSHDQlKjwdn6KGwEbFDn3E
xHcmhVDsp+LCMOvSYAAAAEDjO2NV+k762iQqWZKLhyDBLKf+QaLJh+l6r0xwoHDY
eilDN9IcNCUqPB2foobARsUOfcTEdyaFUOyn4sIw69JgAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClDN9IcNCUqPB2foobARsUOfcTEdyaFUOyn4sIw69Jg
SHA256:FPcDTasqNGQjvNi7zNOF/NyTNMwra8/HhgG6AdODhcs=
SSH Keys Processed = 48055273
Total execution time 4m29.892944s

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
