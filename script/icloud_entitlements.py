#!/usr/bin/env python3
"""Entitlements for a release that syncs join URLs through iCloud key-value storage.

Reads a decoded Developer ID provisioning profile (`security cms -D`) and writes the
app entitlements only when the profile is for ai.sliccy.mac on team S8LB56P782, is
unexpired, carries no debugging entitlement, and authorizes the key-value container
shared with slicc's Sliccstart and iOS follower. Anything else fails the release.
"""
import datetime
import plistlib
import sys

TEAM = 'S8LB56P782'
APP = f'{TEAM}.ai.sliccy.mac'
CONTAINER = f'{TEAM}.ai.sliccy.trays'
KVSTORE = 'com.apple.developer.ubiquity-kvstore-identifier'


def authorizes(granted, value):
    if not isinstance(granted, str):
        return False
    return granted == value or (granted.endswith('*') and value.startswith(granted[:-1]) and granted.startswith(f'{TEAM}.'))


def entitlements(profile, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    granted = profile.get('Entitlements')
    if not isinstance(granted, dict):
        raise ValueError('profile-entitlements')
    if profile.get('TeamIdentifier') != [TEAM] or granted.get('com.apple.developer.team-identifier') != TEAM:
        raise ValueError('profile-team')
    if granted.get('com.apple.application-identifier') != APP:
        raise ValueError('profile-app')
    if granted.get('com.apple.security.get-task-allow') is True or profile.get('ProvisionsAllDevices') is not True:
        raise ValueError('profile-distribution')
    expires = profile.get('ExpirationDate')
    if not isinstance(expires, datetime.datetime):
        raise ValueError('profile-expiry')
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=datetime.timezone.utc)
    if expires <= now:
        raise ValueError('profile-expired')
    if not authorizes(granted.get(KVSTORE), CONTAINER):
        raise ValueError('profile-kvstore')
    return {
        'com.apple.application-identifier': APP,
        'com.apple.developer.team-identifier': TEAM,
        KVSTORE: CONTAINER,
    }


def main(argv):
    if len(argv) != 3:
        print('usage: icloud_entitlements.py <decoded-profile.plist> <entitlements.plist>', file=sys.stderr)
        return 2
    with open(argv[1], 'rb') as source:
        profile = plistlib.load(source)
    try:
        result = entitlements(profile)
    except ValueError as error:
        print(f'Provisioning profile rejected: {error}', file=sys.stderr)
        return 1
    with open(argv[2], 'wb') as target:
        plistlib.dump(result, target)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
