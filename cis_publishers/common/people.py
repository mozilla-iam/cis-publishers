import functools
import json
import logging
import requests

from os import environ
from urllib.parse import quote


# Lazily load all the things
BEARER_TOKEN = None
CHANGE_API_URL = None
NULL_PROFILE = None
OAUTH_AUDIENCE = None
PERSON_API_URL = None
TOKEN_ENDPOINT = None

logger = logging.getLogger()


def __get_bearer_token():
    global BEARER_TOKEN, CHANGE_API_URL, OAUTH_AUDIENCE, PERSON_API_URL, TOKEN_ENDPOINT

    if BEARER_TOKEN is not None:
        return BEARER_TOKEN

    if not environ.get("IAM_DISCOVERY_URL"):
        logging.error("IAM_DISCOVERY_URL not set")
        raise EnvironmentError

    # First, we need to retrieve the discovery URL's contents
    discovery = requests.get(environ["IAM_DISCOVERY_URL"]).json()
    CHANGE_API_URL = discovery["api"]["endpoints"]["change"]
    OAUTH_AUDIENCE = discovery["api"]["audience"]
    PERSON_API_URL = discovery["api"]["endpoints"]["person"]
    OIDC_DISCOVERY_URL = discovery["oidc_discovery_uri"]
    TOKEN_ENDPOINT = requests.get(OIDC_DISCOVERY_URL).json()["token_endpoint"]

    # Then, we need to reach out to auth0 to get a bearer token
    BEARER_TOKEN = requests.post(TOKEN_ENDPOINT, json={
        "audience": OAUTH_AUDIENCE,
        "client_id": environ["OAUTH_CLIENT_ID"],
        "client_secret": environ["OAUTH_CLIENT_SECRET"],
        "grant_type": "client_credentials",
    }).json()["access_token"]


def __requires_bearer_token(func, *args, **kwargs):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Simply return back if there were no args or kwargs passed, so that we don't retrieve
        # the bearer tokens if not necessary
        if BEARER_TOKEN is None and (any(args) or any(kwargs)):
            __get_bearer_token()

        return func(*args, **kwargs)

    return wrapper


# TODO: should it return a skeleton profile? or should that be another function call?
@__requires_bearer_token
def get_profile(email: str = None, user_id: str = None, username: str = None):
    global NULL_PROFILE

    if len([arg for arg in (email, user_id, username) if arg is not None]) > 1:
        raise ValueError("Cannot specify more than one of email, user_id, or username")

    if not any((email, user_id, username)):
        if not NULL_PROFILE:
            NULL_PROFILE = requests.get(environ["CIS_NULL_PROFILE_URL"]).json()

        return NULL_PROFILE

    elif email is not None:
        url = f"{PERSON_API_URL}/v2/user/primary_email/{quote(email)}?active=any"
    elif user_id is not None:
        url = f"{PERSON_API_URL}/v2/user/user_id/{quote(user_id)}?active=any"
    elif username is not None:
        url = f"{PERSON_API_URL}/v2/user/primary_username/{quote(username)}?active=any"

    # Now, let's connect to the Person API and retrieve the profile
    profile = requests.get(url, headers={
        "Authorization": f"Bearer {BEARER_TOKEN}"
    }).json()

    if not profile:
        from .profile import ProfileNotFoundException

        raise ProfileNotFoundException("Unable to load profile for: "
                                       f"{email if email is not None else ''}"
                                       f"{user_id if user_id is not None else ''}"
                                       f"{username if username is not None else ''}")

    return profile


def change_profile(profile):
    if isinstance(profile, str):
        profile = json.loads(profile)
    elif isinstance(profile, dict):
        pass
    else:
        # If it's a ProfileDict, we need to serialize (with a default dict), and then back to a dictionary
        # I know this is inefficient, but you can't easily read the values out of a ProfileDict
        profile = json.loads(json.dumps(profile, default=dict))

    # Get the user_id from the profile
    user_id = profile["user_id"]["value"]

    # Make sure all the required attributes are in the profile
    if None in ([user_id, profile["primary_email"], profile["primary_username"]]):
        raise ValueError("Can't send to Change API without a user_id, primary_email, and primary_username in profile")

    url = f"{CHANGE_API_URL}/v2/user?user_id={user_id}"

    r = requests.post(url, headers={
        "Authorization": f"Bearer {BEARER_TOKEN}"
    }, json=profile).json()

    if r.get("status_code") == 200:
        logger.debug(f"Successfully updated LDAP profile `{user_id}`")

        return True
    else:
        error = f": [{r.get('code')}] {r.get('description')}" if "code" in r else ""
        logger.error(f"Unable to update LDAP profile `{user_id}`{error}")

        return False
