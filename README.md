# Super-simplified threat management for personal computing needs

## Computing personal security through super-simplified threat modeling

This quick&dirty script calculates which security domains (devices) can host which activities (usecases).

Useful for deciding how to secure personal computing needs.

Required reading:

* https://en.wikipedia.org/wiki/Threat_model
* https://en.wikipedia.org/wiki/Computer_security_model
* https://en.wikipedia.org/wiki/Information_security


Example output:

```
primary_pocket_computer, primary_laptop_computer, gsm_phone, computer_sec, phone_banking_sim, android_secure
---------------------------------------------
primary_pocket_computer
  phys=2, near=1, remote=1
 * usecase_personal_computing, usecase_personal_keepass, usecase_android_device, usecase_personal_google_account_android
primary_laptop_computer
  phys=2, near=1, remote=1
 * usecase_nongsm_device, usecase_personal_keepass, usecase_nonotp_device, usecase_personal_computing, usecase_computer, usecase_personal_google_account_computer
 * usecase_sometimes_login_to_work_email
gsm_phone
  phys=2, near=1, remote=1
 * usecase_personal_gsm_sim, usecase_android_device
 * usecase_junk_apps
 * usecase_freeotp_work
computer_sec
  phys=2, near=2, remote=2
 * usecase_secure_keepass, usecase_nongsm_device, usecase_personal_keepass, usecase_nonotp_device, usecase_computer, usecase_secure_computing
phone_banking_sim
  phys=1, near=1, remote=1
 * usecase_too_old_android, usecase_banking_gsm_sim, usecase_android_device
android_secure
  phys=2, near=2, remote=2
 * usecase_secure_keepass, usecase_android_device
 * usecase_secure_keepass
 * usecase_banking_app
 * usecase_secure_google_account
 * usecase_freeotp_personal

---------------------------------------------
```

