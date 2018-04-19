# Computing Personal Security Through Super-Simplified Threat Modeling

# This quick&dirty script calculates which security domains (devices) can host which activities (usecases).
# Useful for deciding how to secure personal computing needs.


# Example output:
# 
# primary_pocket_computer, primary_laptop_computer, gsm_phone, computer_sec, phone_banking_sim, android_secure
# ---------------------------------------------
# 
# primary_pocket_computer
#   phys=2, near=1, remote=1
#  * usecase_personal_keepass, usecase_personal_google_account_android, usecase_bluetooth_music, usecase_personal_computing, usecase_android_device
# 
# primary_laptop_computer
#   phys=2, near=1, remote=1
#  * usecase_nongsm_device, usecase_personal_keepass, usecase_nonotp_device, usecase_computer, usecase_personal_google_account_computer, usecase_personal_computing
#  * usecase_sometimes_login_to_work_email
# 
# gsm_phone
#   phys=2, near=1, remote=1
#  * usecase_personal_gsm_sim, usecase_android_device
#  * usecase_freeotp_work
#  * usecase_junk_apps
# 
# computer_sec
#   phys=2, near=2, remote=2
#  * usecase_secure_keepass, usecase_nongsm_device, usecase_personal_keepass, usecase_nonotp_device, usecase_computer, usecase_secure_computing
#  * usecase_secure_google_account
# 
# phone_banking_sim
#   phys=1, near=1, remote=1
#  * usecase_android_device, usecase_banking_gsm_sim, usecase_too_old_android
# 
# android_secure
#   phys=2, near=2, remote=2
#  * usecase_secure_keepass, usecase_android_device
#  * usecase_freeotp_personal
#  * usecase_banking_app
# ---------------------------------------------
# 
# 

import random

# attack difficulties for the individual localities (physical, near, remote)
DIFF_IMPOSSIBLE = 3
DIFF_HARD = 2
DIFF_EASY = 1
DIFF_TRIVIAL = 0


class AttackVector:
    # Physical attack - the attacker has to physically do something with the device
    #   * impossible
    #   * hard - The attacker has to perform a non-trivial procedure and/or spend considerable time
    #     tinkering with the device and/or do an obvious suspicious action in a monitored space -
    #     e.g. take off the case & install a SIM card & turn off airplane mode & activate SIM card
    #     & do a further action
    #   * easy - The attacker has to perform a simple quick action - e.g. plug a usb, turn off
    #     airplane mode, steal the device
    #   * trivial - e.g. no lockscreen, no encryption.
    # Nearby attack - the attacker has to be in the vicinity of the device
    #   * impossible
    #   * hard - The attacker has to perform a non-trivial procedure and/or spend considerable time
    #     with the procedure and/or do an obvious suspicious action in a monitored space - e.g. wait
    #     nearby until the SIM card is turned on and logged to the network and then get root on the
    #     device within 2 minutes
    #   * easy - The attacker has to perform a simple quick action - e.g. plug a usb, turn off
    #     airplane mode, steal the device; e.g. (future-wise assumption) plant a scripted fake base
    #     station near workplace that uses a slow method to get root on a permanently running device
    #      with GSM enabled
    #   * trivial - e.g. open telnet login without password, insecure services listening unfirewalled
    # Remote attack - the attacker is somewhere on the network
    #   * impossible
    #   * hard - The attacker has to perform a non-trivial procedure and/or spend considerable time
    #     with the procedure - e.g. get root through attack on TLS chained with code execution
    #   * easy - The attacker has to perform a simple action - e.g. rent an exploit kit, insert it
    #     into an ad, display it on the device
    #   * trivial - e.g. open telnet login without password, insecure services listening unfirewalled
    def __init__(self, max_sec_phys, max_sec_near, max_sec_remote):
        # maximum achievable security when the attack vector is considered (the applicable device
        # can't have higher security than that)
        self.max_sec_phys = max_sec_phys
        self.max_sec_near = max_sec_near
        self.max_sec_remote = max_sec_remote


# Attack vectors and their required skill levels.
# _hard attack vectors require a very skilled attacker and/or very special knowledge or equipment.
#   * e.g. remote rooting into a phone through GSM that is turned on for only 2 minutes
#   * e.g. remote rooting into a phone through GSM that is running without SIM card
#   * e.g. MITM into TLS communication of a banking app
#   * e.g. getting data off a locked encrypted device that is not vulnerable through connected
#     network or USB
#   * e.g. code execution on device through a hardened app, such as internet banking app
# _easy attack vectors
#   * e.g. rooting into a phone through ad that hosts an exploit kit
#   * e.g. (future-wise assumption) rooting into a phone through GSM that is running with a valid
#     SIM card all the time
#   * e.g. code execution on device through an ad-laden app with excessive permissions, or through
#     an insecurely made app

# Use your own judgement here.

# Even a remote attack can somehow facilitate a physical attack, in theoretical scenarios stretched
# enough.
attack_net_hard = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                               max_sec_remote=DIFF_HARD)
attack_net_easy = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_EASY,
                               max_sec_remote=DIFF_EASY)

# A physical attack can theoretically facilitate a remote attack, e.g. by disabling airplane mode.
attack_phys_hard = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                                max_sec_remote=DIFF_HARD)
attack_phys_easy = AttackVector(max_sec_phys=DIFF_EASY, max_sec_near=DIFF_EASY,
                                max_sec_remote=DIFF_HARD)

# 2 minutes of GSM use for banking 2FA SMS.
attack_gsm_hard = AttackVector(max_sec_phys=DIFF_IMPOSSIBLE, max_sec_near=DIFF_HARD,
                               max_sec_remote=DIFF_HARD)

# Normal mobile phone use.
attack_gsm_easy = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_EASY,
                               max_sec_remote=DIFF_EASY)

# Hardened simple apps like FreeOTP, banking app, keepass.
attack_app_hard = AttackVector(max_sec_phys=DIFF_IMPOSSIBLE, max_sec_near=DIFF_HARD,
                               max_sec_remote=DIFF_HARD)

# Normal apps with carefully selected permissions.
attack_app_medium = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                                 max_sec_remote=DIFF_EASY)

# Junk apps, apps with ads, apps with too many permissions, suspicious apps.
attack_app_easy = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                               max_sec_remote=DIFF_EASY)

# Attacker sees encrypted traffic or attacker can execute code on a logged-in android device (but
# not on a logged-in desktop).
attack_google_hard = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                                  max_sec_remote=DIFF_HARD)

# Attacker can access the google account from a logged-in desktop, can sniff & spoof the password
# and 2FA.
attack_google_easy = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                                  max_sec_remote=DIFF_EASY)

# Attacker gets root inside the wifi radio chip and manipulates traffic.
attack_wifi_hard = AttackVector(max_sec_phys=DIFF_IMPOSSIBLE, max_sec_near=DIFF_HARD,
                                max_sec_remote=DIFF_HARD)

# Attacker takes advantage of insecure app that listens, exploits it to unlock the device, or
# exploits it to get root.
# OR attacker can manipulate plaintext traffic.
attack_wifi_easy = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_EASY,
                                max_sec_remote=DIFF_HARD)

# The bluetooth assumptions are somewhat wrong and specific to a certain usecase, do use your own
# judgement.

# Attacker exploits the device with enabled bluetooth while the device is not trying to connect with
# anything and is not in discoverable mode and wifi is disabled (or doesn't have neighboring MACs).
attack_bluetooth_hard = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_EASY,
                                     max_sec_remote=DIFF_HARD)

# Attacker exploits the device with enabled bluetooth while the device is communicating and bluetooth
# is dicoverable / wifi is enabled (neighboring MACs)
# Also assuming that the attacker installs code that allows remote control.
attack_bluetooth_easy = AttackVector(max_sec_phys=DIFF_HARD, max_sec_near=DIFF_EASY,
                                     max_sec_remote=DIFF_EASY)


class Usecase:
    # A usecase has minimum security requirement for the usecase to be safe to do.
    # A usecase can also open the device it's performed on to additional attack vectors.
    # A usecase can also collide with other usecases - it cannot be performed on the device if a
    # specific colliding usecase is also performed on the device
    def __init__(self, name, req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                 req_min_sec_remote=DIFF_EASY, introduces_attack_vectors=None,
                 colliding_usecases=None):
        self.name = name
        self.req_min_sec_phys = req_min_sec_phys
        self.req_min_sec_near = req_min_sec_near
        self.req_min_sec_remote = req_min_sec_remote
        self.introduces_attack_vectors = set(
            introduces_attack_vectors) if introduces_attack_vectors else set()
        self.colliding_usecases = set(colliding_usecases) if colliding_usecases else set()
        if not self.calculate_usecase_sec_reqs():
            raise Exception("Usecase {} is impossible.".format(self.name))

    def calculate_usecase_max_sec(self):
        # attack vectors make the maximum achievable security lower
        # -> calculate the lowest of them all
        sp = DIFF_IMPOSSIBLE
        sn = DIFF_IMPOSSIBLE
        sr = DIFF_IMPOSSIBLE
        for v in self.introduces_attack_vectors:
            sp = min(sp, v.max_sec_phys)
            sn = min(sn, v.max_sec_near)
            sr = min(sr, v.max_sec_remote)
        return sp, sn, sr

    def calculate_usecase_sec_reqs(self):
        ok = True
        sp, sn, sr = self.calculate_usecase_max_sec()
        ok &= self.req_min_sec_phys <= sp
        ok &= self.req_min_sec_near <= sn
        ok &= self.req_min_sec_remote <= sr
        return ok


usecase_freeotp_personal = Usecase(name="usecase_freeotp_personal",
                                   req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                                   req_min_sec_remote=DIFF_EASY,
                                   introduces_attack_vectors=None)

usecase_freeotp_work = Usecase(name="usecase_freeotp_work",
                               req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                               req_min_sec_remote=DIFF_EASY,
                               introduces_attack_vectors=None)

usecase_bluetooth_music = Usecase(name="usecase_bluetooth_music",
                                  req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                                  req_min_sec_remote=DIFF_EASY,
                                  introduces_attack_vectors=[attack_bluetooth_easy])

usecase_personal_gsm_sim = Usecase(name="usecase_personal_gsm_sim",
                                   req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                                   req_min_sec_remote=DIFF_EASY,
                                   introduces_attack_vectors=[attack_gsm_easy])

# Even if we ignore the fact that everyday GSM use lowers the device's security (which this script
# should calculate),
# having a separate unknown number for banking is good security through obscurity. Ignoring 2-SIM
# phones here.
# Banking 2FA SMS relies on an insecure channel - the GSM network (and related networks) - so the
# REAL minimum required security
# is sadly low.
# If the device provides low physical security (DIFF_EASY), it should be turned off when not in use.
usecase_banking_gsm_sim = Usecase(name="usecase_banking_gsm_sim",
                                  req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                                  req_min_sec_remote=DIFF_EASY,
                                  introduces_attack_vectors=[attack_gsm_hard],
                                  colliding_usecases=[usecase_personal_gsm_sim])

# I just refuse to do anything with this account on a device with any GSM SIM used, even for one
# minute.
usecase_banking_app = Usecase(name="usecase_banking_app",
                              req_min_sec_phys=DIFF_HARD, req_min_sec_near=DIFF_HARD,
                              req_min_sec_remote=DIFF_HARD,
                              introduces_attack_vectors=[attack_net_hard, attack_app_hard,
                                                         attack_wifi_hard],
                              colliding_usecases=[usecase_banking_gsm_sim,
                                                  usecase_personal_gsm_sim])

# Personal google account is for everyday use on those kinds of devices that can be remotely attacked
# e.g. through exploits in ads.
# Assuming it is non-trivial to misuse a logged in account on an android device to surreptitiously
# install apps on another device
# Banking SIM also used for recovery of the google account, so it can't be on the same device.
# Personal FreeOTP has 2FA for the personal google account, so it can't be on the same device.
usecase_personal_google_account_android = Usecase(name="usecase_personal_google_account_android",
                                                  req_min_sec_phys=DIFF_HARD,
                                                  req_min_sec_near=DIFF_EASY,
                                                  req_min_sec_remote=DIFF_EASY,
                                                  introduces_attack_vectors=[attack_google_hard,
                                                                             attack_net_hard,
                                                                             attack_app_hard,
                                                                             attack_wifi_hard],
                                                  colliding_usecases=[usecase_banking_gsm_sim,
                                                                      usecase_freeotp_personal])

# Personal google account is for everyday use on those kinds of devices that can be remotely attacked
# e.g. through exploits in ads.
# Assuming it is trivial to misuse a logged in account on a desktop computer to surreptitiously
# install apps on another device
# Banking SIM also used for recovery of the google account, so it can't be on the same device.
# Personal FreeOTP has 2FA for the personal google account, so it can't be on the same device.
usecase_personal_google_account_computer = Usecase(name="usecase_personal_google_account_computer",
                                                   req_min_sec_phys=DIFF_HARD,
                                                   req_min_sec_near=DIFF_EASY,
                                                   req_min_sec_remote=DIFF_EASY,
                                                   introduces_attack_vectors=[attack_google_easy,
                                                                              attack_net_hard,
                                                                              attack_app_hard,
                                                                              attack_wifi_hard],
                                                   colliding_usecases=[usecase_banking_gsm_sim,
                                                                       usecase_freeotp_personal])

usecase_junk_apps = Usecase(name="usecase_junk_apps",
                            req_min_sec_phys=DIFF_TRIVIAL, req_min_sec_near=DIFF_TRIVIAL,
                            req_min_sec_remote=DIFF_TRIVIAL,
                            introduces_attack_vectors=[attack_app_easy, attack_net_easy,
                                                       attack_wifi_easy],
                            colliding_usecases=[])

usecase_work = Usecase(name="usecase_work",
                       req_min_sec_phys=DIFF_HARD,
                       req_min_sec_near=DIFF_HARD,
                       req_min_sec_remote=DIFF_HARD,
                       colliding_usecases=[usecase_freeotp_personal,
                                           usecase_freeotp_work,
                                           usecase_bluetooth_music,
                                           usecase_personal_gsm_sim,
                                           usecase_banking_gsm_sim,
                                           usecase_banking_app,
                                           usecase_personal_google_account_android,
                                           usecase_personal_google_account_computer,
                                           usecase_junk_apps,
                                           ])

# I just refuse to do anything with this account on a device with any GSM SIM used, even for one
# minute.
usecase_secure_google_account = Usecase(name="usecase_secure_google_account",
                                        req_min_sec_phys=DIFF_HARD, req_min_sec_near=DIFF_HARD,
                                        req_min_sec_remote=DIFF_HARD,
                                        introduces_attack_vectors=[attack_google_hard,
                                                                   attack_app_hard,
                                                                   attack_wifi_hard],
                                        # if used on an android device as a logged in android account
                                        colliding_usecases=[usecase_banking_gsm_sim,
                                                            usecase_personal_gsm_sim,
                                                            usecase_work])

# I just refuse to do anything with this account on a device with any GSM SIM used, even for one
# minute.
usecase_secure_keepass = Usecase(name="usecase_secure_keepass",
                                 req_min_sec_phys=DIFF_HARD, req_min_sec_near=DIFF_HARD,
                                 req_min_sec_remote=DIFF_HARD,
                                 introduces_attack_vectors=[attack_app_hard],
                                 colliding_usecases=[usecase_banking_gsm_sim,
                                                     usecase_personal_gsm_sim,
                                                     usecase_work])

# This is the keepass that largely contains web logins that are also saved in a web browser, so I
# have to be realistic, that it
# is for use on a device exploitable e.g. through malicious ads.
# Must not be used on the same device where the accompanying 2FA app is used. (so that the two
# factors are separate)
# But I refuse to do anything with it on a phone that has GSM SIM enabled most of the time.
usecase_personal_keepass = Usecase(name="usecase_personal_keepass",
                                   req_min_sec_phys=DIFF_HARD, req_min_sec_near=DIFF_EASY,
                                   req_min_sec_remote=DIFF_EASY,
                                   introduces_attack_vectors=[attack_app_hard],
                                   colliding_usecases=[usecase_personal_gsm_sim,
                                                       usecase_freeotp_personal,
                                                       usecase_work])

usecase_windows_apps_games_careful = Usecase(name="usecase_windows_apps_games_careful",
                                             req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                                             req_min_sec_remote=DIFF_EASY,
                                             introduces_attack_vectors=[attack_app_medium,
                                                                        attack_net_easy],
                                             colliding_usecases=[])

# My main usecase for a (pocket/desktop) computer device.
# But I refuse to do anything with it on a phone that has GSM SIM enabled most of the time.
usecase_personal_computing = Usecase(name="usecase_personal_computing",
                                     req_min_sec_phys=DIFF_HARD, req_min_sec_near=DIFF_EASY,
                                     req_min_sec_remote=DIFF_EASY,
                                     introduces_attack_vectors=[attack_app_hard, attack_net_easy,
                                                                attack_wifi_hard],
                                     colliding_usecases=[usecase_personal_gsm_sim,
                                                         usecase_junk_apps])

# Some light tasks, not having most of my data on the device, not logging in my online accounts,
# mostly programming and using just my second limited dropbox account.
usecase_personal_computing_lite = Usecase(name="usecase_personal_computing_lite",
                                          req_min_sec_phys=DIFF_EASY, req_min_sec_near=DIFF_EASY,
                                          req_min_sec_remote=DIFF_EASY,
                                          introduces_attack_vectors=[attack_app_hard,
                                                                     attack_net_easy,
                                                                     attack_wifi_hard],
                                          colliding_usecases=[usecase_personal_gsm_sim])

usecase_secure_computing = Usecase(name="usecase_secure_computing",
                                   req_min_sec_phys=DIFF_HARD, req_min_sec_near=DIFF_HARD,
                                   req_min_sec_remote=DIFF_HARD,
                                   introduces_attack_vectors=[attack_app_hard, attack_net_hard,
                                                              attack_wifi_hard],
                                   colliding_usecases=[usecase_personal_gsm_sim,
                                                       usecase_banking_gsm_sim, usecase_work])

# Just to mark a device that it has no GSM capabilities.
usecase_nongsm_device = Usecase(name="usecase_nongsm_device",
                                colliding_usecases=[usecase_personal_gsm_sim,
                                                    usecase_banking_gsm_sim])

# Just to mark a device that it can't be used for OTP. (E.g. because I can't carry it in my purse.)
usecase_nonotp_device = Usecase(name="usecase_nonotp_device",
                                colliding_usecases=[usecase_freeotp_work, usecase_freeotp_personal])

# Can't use android apps
usecase_computer = Usecase(name="usecase_computer",
                           colliding_usecases=[usecase_banking_app,
                                               usecase_personal_google_account_android,
                                               usecase_junk_apps,
                                               usecase_freeotp_work, usecase_freeotp_personal])

# Not used exactly as a desktop computer
usecase_android_device = Usecase(name="usecase_android_device",
                                 colliding_usecases=[usecase_personal_google_account_computer])

# The phone is too old and shitty to run most of stuff even if I wanted
usecase_too_old_android = Usecase(name="usecase_too_old_android",
                                  colliding_usecases=[usecase_personal_google_account_computer,
                                                      usecase_banking_app, usecase_junk_apps,
                                                      usecase_personal_keepass,
                                                      usecase_secure_keepass,
                                                      usecase_secure_google_account,
                                                      usecase_personal_google_account_android,
                                                      usecase_personal_gsm_sim,
                                                      usecase_personal_computing,
                                                      usecase_secure_computing])

# All operating systems and their different browsers have no ad blocker whatsoever, so that's at
# least one reason
# why the minimum required remote security is only DIFF_EASY. Also, TLS is used, so the minimum
# required nearby
# security is DIFF_EASY as well.
# I store no work-related passwords in any of my keepass, so no further collisions here.
usecase_sometimes_login_to_work_email = Usecase(name="usecase_sometimes_login_to_work_email",
                                                req_min_sec_phys=DIFF_HARD,
                                                req_min_sec_near=DIFF_EASY,
                                                req_min_sec_remote=DIFF_EASY,
                                                colliding_usecases=[usecase_freeotp_work])


class Device:
    # The device itself has characteristics that limit the maximum security.
    # It also has usecases that invariably must be done on that device.
    def __init__(self, name, pinned_usecases=None, additional_usecases=None,
                 max_sec_phys=DIFF_IMPOSSIBLE, max_sec_near=DIFF_IMPOSSIBLE,
                 max_sec_remote=DIFF_IMPOSSIBLE):
        self.name = name
        self.pinned_usecases = set(pinned_usecases) if pinned_usecases else set()
        self.additional_usecases = set(additional_usecases) if additional_usecases else set()
        self.max_sec_phys = max_sec_phys
        self.max_sec_near = max_sec_near
        self.max_sec_remote = max_sec_remote
        if not self.works():
            raise Exception(self.name + " default requirements are impossible")

    def calculate_usecase_collisions(self):
        mentioned_collisions = set()
        usecases = self.pinned_usecases | self.additional_usecases
        for u in usecases:
            mentioned_collisions |= u.colliding_usecases
        # some of the active usecases are mentioned by some other usecases as colliding
        collisions = mentioned_collisions.intersection(usecases)
        return collisions

    def calculate_usecase_max_sec(self):
        # attack vectors make the maximum achievable security lower
        # -> calculate the lowest of them all
        sp = self.max_sec_phys
        sn = self.max_sec_near
        sr = self.max_sec_remote
        usecases = self.pinned_usecases | self.additional_usecases
        for u in usecases:
            for v in u.introduces_attack_vectors:
                sp = min(sp, v.max_sec_phys)
                sn = min(sn, v.max_sec_near)
                sr = min(sr, v.max_sec_remote)
        return sp, sn, sr

    def calculate_usecase_sec_reqs(self):
        ok = True
        sp, sn, sr = self.calculate_usecase_max_sec()
        usecases = self.pinned_usecases | self.additional_usecases
        for u in usecases:
            ok &= u.req_min_sec_phys <= sp
            ok &= u.req_min_sec_near <= sn
            ok &= u.req_min_sec_remote <= sr
        return ok

    def works(self):
        nocollisions = not self.calculate_usecase_collisions()
        reqs_met = self.calculate_usecase_sec_reqs()
        if nocollisions and reqs_met:
            return True
        return False

    def copy(self):
        return Device(name=self.name,
                      pinned_usecases=self.pinned_usecases,
                      additional_usecases=self.additional_usecases,
                      max_sec_phys=self.max_sec_phys,
                      max_sec_near=self.max_sec_near,
                      max_sec_remote=self.max_sec_remote)


primary_pocket_computer = Device(name="primary_pocket_computer",
                                 pinned_usecases=[usecase_android_device,
                                                  usecase_personal_computing,
                                                  usecase_personal_google_account_android,
                                                  usecase_personal_keepass,
                                                  usecase_bluetooth_music],
                                 max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                                 max_sec_remote=DIFF_HARD)

# TODO the susceptibility to bootkits and keyloggers should make physical security DIFF_EASY?
primary_laptop_computer = Device(name="primary_laptop_computer",
                                 pinned_usecases=[usecase_computer, usecase_nongsm_device,
                                                  usecase_nonotp_device,
                                                  usecase_personal_computing,
                                                  usecase_personal_keepass,
                                                  usecase_personal_google_account_computer, ],
                                 max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD,
                                 max_sec_remote=DIFF_HARD)

gsm_phone = Device(name="gsm_phone",
                   pinned_usecases=[usecase_android_device, usecase_personal_gsm_sim],
                   max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD, max_sec_remote=DIFF_HARD)

computer_sec = Device(name="computer_sec",
                      pinned_usecases=[usecase_computer, usecase_nongsm_device,
                                       usecase_nonotp_device,
                                       usecase_secure_computing, usecase_secure_keepass,
                                       usecase_personal_keepass],
                      max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD, max_sec_remote=DIFF_HARD)

phone_banking_sim = Device(name="phone_banking_sim",
                           pinned_usecases=[usecase_android_device, usecase_too_old_android,
                                            usecase_banking_gsm_sim],
                           # it's an old phone, it has to be powered off when not in use to mitigate
                           # most of the attack surface
                           max_sec_phys=DIFF_EASY, max_sec_near=DIFF_EASY, max_sec_remote=DIFF_EASY)

android_secure = Device(name="android_secure",
                        pinned_usecases=[usecase_android_device,
                                         usecase_secure_keepass],
                        max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD, max_sec_remote=DIFF_HARD)

windows_tablet = Device(name="windows_tablet",
                        pinned_usecases=[usecase_computer, usecase_nongsm_device,
                                         usecase_nonotp_device, usecase_windows_apps_games_careful,
                                         usecase_personal_computing_lite],
                        max_sec_phys=DIFF_EASY, max_sec_near=DIFF_HARD, max_sec_remote=DIFF_EASY)

# ignoring intel AMT
work_computer = Device(name="work_computer",
                       pinned_usecases=[usecase_computer, usecase_nongsm_device,
                                        usecase_nonotp_device, usecase_work, ],
                       max_sec_phys=DIFF_HARD, max_sec_near=DIFF_HARD, max_sec_remote=DIFF_HARD)

devices = [primary_pocket_computer, primary_laptop_computer, gsm_phone, computer_sec,
           phone_banking_sim, android_secure, windows_tablet, work_computer]

# usecases to distribute, each usecase to one device
usecases = [usecase_freeotp_personal, usecase_freeotp_work, usecase_banking_app,
            usecase_secure_google_account, usecase_junk_apps, usecase_sometimes_login_to_work_email]


def random_device_usecase_assignment(devices, usecases):
    cp_dev = [d.copy() for d in devices]
    cp_use = set(usecases)
    while cp_use:
        which_dev = random.randint(0, len(cp_dev) - 1)
        how_many_usecases = random.randint(0, len(cp_use))
        l_u = list(cp_use)
        random.shuffle(l_u)
        for i in range(how_many_usecases):
            cp_dev[which_dev].additional_usecases.add(l_u[i])
            cp_use.remove(l_u[i])
    return cp_dev


def print_device_usecase_assignment(devices):
    print("")
    print("")
    print(", ".join([x.name for x in devices]))
    print("---------------------------------------------")
    for d in devices:
        print("")
        print(d.name)
        print("  phys={}, near={}, remote={}".format(*d.calculate_usecase_max_sec()))
        if d.pinned_usecases:
            print(" * " + ", ".join([x.name for x in d.pinned_usecases]))
        for u in d.additional_usecases:
            print(" * " + u.name)
    print("---------------------------------------------")
    print("")


def device_assignment_ok(devices):
    ok = True
    for d in devices:
        ok &= d.works()
    return ok


# NOTE - The initial check can be used for experimenting and to incrementally find out which pinned
# usecases work together and which don't.
print("Initial check - the set of devices and their pinned usecases can work: " + repr(
    device_assignment_ok(devices)))

for i in range(1):
    while True:  # brute force, if it hangs too long, there's _probably_ no solution
        test1 = random_device_usecase_assignment(devices, usecases)
        if device_assignment_ok(test1):
            print_device_usecase_assignment(test1)
            break

# TODO cross-device attacks
#       - seeing banking 2FA sms is not bad for the phone but bad if the attacker has credentials to
#           the bank
#       - mobile phone can be attackable through logged in google account on a desktop computer under
#           some conditions
#           - NOTE: it looks like Google made it so that if a particular desktop session is not used
#               for app installations, then any installation attempt is behind a login screen, which
#               seems an adequate mitigation
# TODO finer preferences - having junk apps on primary pocket computer is not bad per the computed
#   policies but I prefer not to do that
# TODO better handling of chained attacks - e.g. attacker turns off airplane mode to let the device
#   connect to gsm/wifi that is vulnerable and performs an attack through that
