import boto3
import concurrent.futures
import json
import logging
import lzma
import time

from cis_publishers.common import InactiveProfileException, Profile, ProfileNotFoundException
from inspect import cleandoc
from os import environ
from os.path import exists


logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())


def handle(event: dict, context=None) -> int:
    main()

    return None


def get_ldap_dump(bucket: str = None, key: str = None, filename: str = None) -> dict:
    """
    :param bucket: bucket name in S3
    :param key:  LDAP dump file name in S3
    :param filename: file name when running locally
    :return: contents of compressed (or uncompressed) LDAP dump, as a dictionary
    """
    if bucket and key:
        s3 = boto3.client("s3")

        logger.info("Reloading LDAP data from S3")

        s3object = s3.get_object(Bucket=bucket,
                                 Key=key)["Body"]

        if environ["LDAP_CACHE_S3_KEY"].endswith("xz"):
            with lzma.open(s3object) as __f:
                return json.load(__f)
        else:
            return json.loads(s3object.read())
    elif filename:
        if not exists(filename):
            raise FileNotFoundError(f"Cannot open {filename}")

        with open(filename, "r") as __f:
            return json.load(__f)


def synchronize(email, ldap_profile):
    # The mapping of LDAP field names to the ldap_profile key names can be found
    # in git-internal.mozilla.org/sysadmins/puppet/modules/ldap_crons/files/ldap_to_cis/ldap_to_cis.py
    # in the structure_output function
    
    # convenience variables to make referring to user profile data cleaner
    dn = ldap_profile["distinguished_name"]
    pgp_public_keys = {f"LDAP-{i}": f"0x{key}".replace(" ", "").replace("0x0x", "0x")
                       for i, key in enumerate(ldap_profile.get("pgp_public_keys", []), start=1)}
    phone_numbers = {f"LDAP-{i}": key.strip()
                     for i, key in enumerate(ldap_profile.get("phone_numbers", []), start=1)}
    ssh_public_keys = {f"LDAP-{i}": key.strip()
                       for i, key in enumerate(ldap_profile.get("ssh_public_keys", []), start=1)}
    user_id = ldap_profile["user_id"]

    # convenience variables to make the code below cleaner
    display_level = "staff" if "o=com" in dn or "o=org" in dn else "private"
    prefix = environ["LDAP_USER_ID_PREFIX"]

    # Update a profile
    try:
        # Note that this is a change from the previous
        p = Profile(email=email)
        logger.debug(f"Updating user: {user_id} ({email})")

        p.update({
            "pgp_public_keys": pgp_public_keys,
            "ssh_public_keys": ssh_public_keys,
        })

        p["access_information"]["ldap"] = ldap_profile.get("groups")

        p["identities"].update({
            "mozilla_ldap_id": ldap_profile.get("distinguished_name"),
            "mozilla_ldap_primary_email": email,
            "mozilla_posix_id": ldap_profile.get("posix", {}).get("uid"),
        })

    except InactiveProfileException:
        # scream and run away, since LDAP and HRIS are desynced - this should only happen when `active` is
        # set to `false` in CIS -- something that only can be done by the HRIS publisher -- but nevertheless
        # their account still appears in the LDAP active account dump
        return False

    # creating a profile
    except ProfileNotFoundException:
        # Hello fellow adventurer, welcome to the bowels of the third (and hopefully final) LDAP publisher.
        # Since you're here, here are some notes from the previous LDAP publisher:

        # Dropped attributes:
        # mobile, im, description, jpegPhoto - these should all now be set in DinoPark
        # usernames["LDAP"] - can find no evidence of it ever working
        # usernames["LDAP-alias-*"] - in theory, this could be set from the previous publisher, but the only
        #                             time it would ever work is on profile creation, and mail aliases are generally
        #                             setup -long- past that point. In theory, there should be a mail_aliases field
        #                             that could be updated

        # Changed attributes:
        # fun_title - now uses the Workday Title(e.g. Senior Engineer), if it exists
        # last_modified - now uses the timestamp from this run instead of the last_modified value in LDAP,
        #                             with the caveat that `created` is still the LDAP created timestamp

        # Added attributes:
        # usernames["LDAP-uuid"] - at the very least, start including the unique LDAP entryUUID, in case
        #                          some future brainiac makes it all work

        # Note that as it currently stands (2020-10-10), the LDAP publisher will only ever UPDATE a profile,
        # it will never CREATE one. This code remains in case the decision ever changes, as it is known to
        # work properly, and it fully documents what would be done should the LDAP publisher ever create profiles.

        return False  # noqa

        p = Profile()

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

        logger.info(f"Creating user: {user_id} ({email})")

    # Currently, only publish a changed profile
    p.publish(display_level=display_level)

    return True


def main():
    start_time = time.time()

    # Open up the LDAP dump (either as json or compressed), in either S3 or locally
    try:
        if environ.get("LDAP_CACHE_S3_BUCKET"):
            ldap_users = get_ldap_dump(bucket=environ["LDAP_CACHE_S3_BUCKET"], key=environ["LDAP_CACHE_S3_KEY"])
        elif environ.get("LDAP_CACHE_FILENAME"):
            ldap_users = get_ldap_dump(filename=environ["LDAP_CACHE_FILENAME"])
        else:
            raise FileNotFoundError("No LDAP dump specified")
    except:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Invalid LDAP export",
            })
        }

    # Create a thread pool of 32 workers to process the LDAP user_ids
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)
    futures = []

    for email, ldap_profile in ldap_users.items():
        futures.append((email, executor.submit(synchronize, email, ldap_profile)))

    executor.shutdown(wait=True)

    # Now we log whether everything went okay
    desynced_accounts = []
    failed_accounts = []
    successful_accounts = []

    for future in futures:
        result = future[1].result()

        if result is True:
            successful_accounts.append(future[0])
        elif result is False:
            desynced_accounts.append(future[0])
        else:
            failed_accounts.append(future[0])

    desynced_accounts_list_msg = f": {', '.join(desynced_accounts)}" if desynced_accounts else ""
    failed_accounts_list_msg = f": {', '.join(failed_accounts)}" if failed_accounts else ""

    result_message = f"""
        LDAP Publisher results:

          {len(successful_accounts)} accounts synchronized.
          {len(desynced_accounts)} accounts have CIS/HRIS/LDAP mismatches{desynced_accounts_list_msg}
          {len(failed_accounts)} accounts failed to synchronize{failed_accounts_list_msg}

        LDAP Publisher completed in {(time.time() - start_time):.2f}s.
        """

    logger.info(cleandoc(result_message))

    # TODO: Once we're done logging, assuming that there were no failed accounts, we can finally store the
    # status of this last run in S3 (or locally)


if __name__ == "__main__":
    main()
