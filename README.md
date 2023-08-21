# QbotPostMortemRegConfDecryptor
QbotPostMortemRegConfDecryptor is a python script/module for decrypting qbot's registry configuration in a post mortem analysis.

Work is based on great publications from [TrustWave](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/decrypting-qakbots-encrypted-registry-keys/) and [Elastic](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/decrypting-qakbots-encrypted-registry-keys/)

## Usage
The main functionality is implemented in two classes QbotConfDecryptor, QbotDecryptedConfValue and is therefore also useable as a module.

The following help message explains the usage as a script:
```
usage: qbot_post_mortem_reg_conf_decryptor.py [-h] -r REGISTRY_HIVE -k KEY -p PASSWORD [-e EXCLUDED_VALUES [EXCLUDED_VALUES ...]]

Qbot config decryptor.

options:
  -h, --help            show this help message and exit
  -r REGISTRY_HIVE, --registry_hive REGISTRY_HIVE
                        Hive file which contains the qbot config (e.g. ./NTUSER.DAT).
  -k KEY, --key KEY     Key where the qbot config is located (e.g. ROOT\SOFTWARE\Microsoft\<random_str>).
  -p PASSWORD, --password PASSWORD
                        Password for decryption. The password is equal to <computer_name.upper()> + <volumes_serialnumber_decimal.upper()> + <username.upper()>.
  -e EXCLUDED_VALUES [EXCLUDED_VALUES ...], --excluded_values EXCLUDED_VALUES [EXCLUDED_VALUES ...]
                        Exclude value if unencrypted or other reasons.
```

## Test samples and campaign id's

| Sha256 | Repository | Campaign | UploadDate |
| ------ | ---------- | -------- | ---------- |
| 532800b423fecbca1ad9934d4f0101c31018f3d34031ffc4107d4ea5763a2a3f | bazaar.abuse.ch | obama271 | 2023-06-22 |
