import logging
import time
from os import environ
from cis_publishers.common import Profile

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

def unused_create_profile(ldap_profile, pgp_public_keys, phone_numbers, email, ssh_public_keys, user_id):
    """
    Note that as it currently stands (2020-10-10), the LDAP publisher will only ever UPDATE a profile,
    it will never CREATE one. The code in /cis_publishers/common/unused_create_profile remains in case
    the decision ever changes, as it is known to work properly, and it fully documents what would be
    done should the LDAP publisher ever create profiles.
    """
    prefix = environ["LDAP_USER_ID_PREFIX"]
    p = Profile()

    # This profile creation code is never used as the LDAP publisher does not create profiles
    p.update({
        "active": True,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                                 time.strptime(ldap_profile["created_at"], "%Y%m%d%H%M%SZ")),
        "first_name": ldap_profile.get("first_name"),
        "fun_title": ldap_profile.get("title", ""),  # workday title, if they have it
        "last_name": ldap_profile.get("last_name"),
        "last_modified": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "pgp_public_keys": pgp_public_keys,
        "phone_numbers": phone_numbers,
        "primary_email": email,
        "ssh_public_keys": ssh_public_keys,
        "user_id": f"{prefix}|{user_id}",  # TODO: ONLY EVER USE PREFIX FOR EMPLOYEES, OTHERWISE QUERY AUTH0 FOR user_id INSTEAD
        "usernames": {
            "LDAP-posix_id": ldap_profile.get("posix", {}).get("uid"),
            "LDAP-posix_uid": ldap_profile.get("posix", {}).get("uid_number"),
            "LDAP-uuid": ldap_profile.get("entry_uuid"),
        },
    })

    p["access_information"]["ldap"] = ldap_profile.get("groups")

    p["identities"].update({
        "mozilla_ldap_id": ldap_profile.get("distinguished_name"),
        "mozilla_ldap_primary_email": email,
        "mozilla_posix_id": ldap_profile.get("posix", {}).get("uid"),
    })
    # This profile creation code is never used as the LDAP publisher does not create profiles
    logger.info(f"Creating user: {user_id} ({email})")
