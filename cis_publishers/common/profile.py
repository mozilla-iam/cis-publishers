import json
import logging
import time

from collections import UserDict
from copy import copy
from os import environ
from jose import jws

from cis_publishers.common import get_profile, change_profile


# The SIGNING_KEY is only needed when you actually sign things; as such,
# we only error out if you actually try to sign something without it being available.
# This allows you to load profiles without needing to have access to it.
if "PUBLISHER_SIGNING_KEY" in environ:
    PUBLISHER_SIGNING_KEY = json.loads(environ["PUBLISHER_SIGNING_KEY"])
else:
    PUBLISHER_SIGNING_KEY = None

DISPLAY_LEVEL = None

logger = logging.getLogger()


class InactiveProfileException(Exception):
    """
    When a profile is loaded, but it comes back as active: false, which this publisher
    is unable to act on, since it requires a manual fix either in LDAP or in HRIS.
    """


class ProfileNotFoundException(Exception):
    """Basic exception when profile isn't found"""


class ProfileDict(UserDict):
    def __init__(self):
        super().__init__()

    def __getitem__(self, k):
        # if isinstance(self.data[k], SignableAttribute):
        #     if "value" in self.data[k]:
        #         return self.data[k]["value"]
        #     else:
        #         return self.data[k]["values"]

        return self.data[k]

    def __setitem__(self, k, v):
        if k in self.data:
            # This makes it so setting _.profile["active"] = True actually sets the signed value to true
            # and doesn't overwrite the signed attribute itself
            if isinstance(self.data[k], SignableAttribute):
                self.data[k].value = v

                return v
            elif isinstance(self.data[k], ProfileDict):
                raise ValueError("Attempted to overwrite profile dictionary with single value")

        else:
            super().__setitem__(k, v)

        return v


class Profile(UserDict):
    """
    Try to represent the extremely complex CIS profile as a simple dictionary you can
    assign to. It tries to maintain two internal dictionaries:

    self._profile -> A ProfileDict (with nested ProfileDict) and SignableAttributes. This represents the raw state
                     of the CIS profile. Accessable via .json(). Updates to it are lazy and are only triggered
                     upon doing a JSON export.
    self.data ->     A simple dictionary representation of the the CIS profile.
    """
    def __init__(self, email: str = None, user_id: str = None, username: str = None, allow_inactive: bool = False):
        super().__init__()

        self._profile = ProfileDict()

        # Retrieve the profile from the Person API (or the skeleton profile if not specified)
        retrieved_profile = get_profile(email, user_id, username)

        self._base_keys = retrieved_profile.keys()  # when calling __getitem__(), this sends you into self.data

        # Pushed the retrieved JSON into a Profile(), and then push that into a dictionary
        self._walk(retrieved_profile, self._profile)
        self._walk(self._profile, self.data)

        # We can't active on inactive profiles unless we're the HRIS publisher
        if allow_inactive is False and self.data["active"] is False:
            raise InactiveProfileException

        # Store the initial state of the Profile, for future diffing purposes?
        # self.__initial_profile = str(self)

        # Store a list of messages passed from SignedAttributes
        self.__notifications = []

    def __getitem__(self, k):
        if k in self.data:
            return self.data[k]

        return getattr(self, k)

    # If it's a base key in a profile, set it into self._profile and self.data
    def __setitem__(self, k, v):
        if k in self._base_keys:
            self.data[k] = v
        else:
            setattr(self, k, v)

    def __str__(self):
        return json.dumps(self.data, indent=2, sort_keys=True)

    def _walk(self, input_node, output_node):
        """
        Walk a CIS profile, either from the "raw" profile (with signatures and metadata and etc.) to a
        basic dictionary representation, or vice versa.

        It can convert from three different modes:
        Person API -> Internal state (ProfileDict + SignableAttribute) [self._profile] <--> Simple dict [self.data]
        """
        for k, v in input_node.items():
            # If it's a string, that means it's something like 'schema' that is unsigned
            # Person API --> self._profile <--> self.data
            if isinstance(v, str):
                output_node[k] = v

            # Synchronize values on calls to .json()
            # self.data -> self._profile
            elif isinstance(output_node.get(k), SignableAttribute):
                if output_node[k].value != v:
                    output_node[k].value = v

            # If it has a value or values setting, we've gotten to an actual key -> value mapping
            # self._profile -> self.data
            elif isinstance(v, SignableAttribute) and "value" in v:
                output_node[k] = v.value

                # if "value" in v:
                #     output_node[k] = v["value"]
                # else:
                #     output_node[k] = v["values"]

            # Has a value or value setting, but it's a dict, indicating that we're reducing from
            # an initial profile (from the skeleton or people) into self._profile
            # Person API -> self._profile
            elif isinstance(v, dict) and ("value" in v or "values" in v):
                output_node[k] = SignableAttribute(v, name=k, parent_profile=self)

            # If it has neither metadata nor signature and is a dictionary, we need to continue
            # traversing downward
            # Person API -> self._profile <- self.data
            elif isinstance(v, dict) and v.get('metadata') is None and v.get('signature') is None:
                if k not in output_node:  # Person API -> self._profile
                    output_node[k] = ProfileDict()

                # PersonAPI -> self._profile <- self.data
                self._walk(v, output_node[k])

            # self._profile -> self.data
            elif isinstance(v, ProfileDict):
                output_node[k] = {}

                self._walk(v, output_node[k])

            # Trying to set an attribute in self.data that can't be moved into self._profile, because it doesn't
            # exists
            else:
                raise ValueError(f"Attempted to set invalid attribute {k} into profile.")

    def is_empty(self) -> bool:
        """
        :return: whether the profile is deletable or not (such as via the inactive user cleanup process)

        TODO: actually use this in the inactive user cleanup process
        """
        usernames = [] if self.data["usernames"] is None else \
            [username for username in self.data["usernames"] if not username.startswith("HACK#")]

        return not any((
            self.data["access_information"]["access_provider"],
            self.data["access_information"]["hris"],
            self.data["access_information"]["ldap"],
            self.data["access_information"]["mozilliansorg"],
            self.data["alternative_name"],
            self.data["description"],
            self.data["identities"]["bugzilla_mozilla_org_id"],
            self.data["identities"]["bugzilla_mozilla_org_primary_email"],
            self.data["identities"]["custom_1_primary_email"],
            self.data["identities"]["custom_2_primary_email"],
            self.data["identities"]["custom_3_primary_email"],
            self.data["identities"]["mozilla_ldap_id"],
            self.data["identities"]["mozilla_ldap_primary_email"],
            self.data["identities"]["mozilla_posix_id"],
            self.data["identities"]["mozilliansorg_id"],
            self.data["languages"],
            self.data["location"],
            self.data["pgp_public_keys"],
            self.data["phone_numbers"],
            self.data["picture"],
            self.data["pronouns"],
            self.data["staff_information"]["cost_center"],
            self.data["staff_information"]["director"],
            self.data["staff_information"]["manager"],
            self.data["staff_information"]["office_location"],
            self.data["staff_information"]["staff"],
            self.data["staff_information"]["team"],
            self.data["staff_information"]["title"],
            self.data["staff_information"]["worker_type"],
            self.data["staff_information"]["wpr_desk_number"],
            self.data["ssh_public_keys"],
            self.data["tags"],
            self.data["timezone"],
            self.data["uris"],
            usernames,
        ))

    def json(self):
        return json.dumps(self._profile, indent=2, default=dict)

    def notify(self, attribute, message):
        """Used by a SignedAttribute to notify the parent profile that an attribute has changed."""
        self.__notifications.append((attribute, message))

    def publish(self, display_level: str = None, dry_run: bool = False):
        self.sign(display_level)

        [logger.info(f"Updating {attribute} on {self.data['primary_email']}: {message}")
         for attribute, message in sorted(self.__notifications)]

        # Only publish the profile if there has been a change to it
        # And if we're not in dry_run mode
        if self.__notifications and not dry_run and environ.get("DRY_RUN") is None:
            change_profile(self.json())
        elif not self.__notifications:
            logger.debug(f"Skipping publication of {self.data['primary_email']} (no changes)")

        return None

    def sign(self, display_level: str = None):
        """
        Sign all modified Profile attributes.
        :return: None
        """
        if display_level is not None:
            global DISPLAY_LEVEL

            DISPLAY_LEVEL = display_level

        self._walk(self.data, self._profile)

        return None


class SignableAttribute(UserDict):
    def __init__(self, attribute, name, parent_profile):
        super().__init__(attribute)
        self.__name = name
        self.__parent_profile = parent_profile

    # abstract away having to know the difference between value and values
    def __contains__(self, k):
        if k in ("value", "values") and ("value" in self.data or "values" in self.data):
            return True

        super().__contains__(self, k)

    # abstract away having to know the difference between "value" and "values"
    def __getattr__(self, k):
        if k in ("value", "values"):
            return self.data.get("value", self.data.get("values"))
        elif k.startswith("_"):
            return super().__getattribute__(k)

        raise ValueError("Cannot get anything besides .value or .values in signed attribute")

    # __setattr__ isn't as strict as it could be, relying on the publishers to not try to set
    # things that they can't. The change/update mechanism is a giant pain to process and work
    # with, and I don't want to have to figure it out in here.
    def __setattr__(self, k, v):
        # CIS doesn't actually deal in arrays, they are always dictionaries with each value set to null
        if isinstance(v, list) and v:
            v = {v: None for v in sorted(v)}

        # Similarly, it doesn't handle numbers either: only strings - not isinstance() since bool is an int
        if type(v) in (int, float):
            v = str(v)

        if k in ("value", "values"):
            key = "value" if "value" in self.data else "values"

            # If we try to set the value to the existing value, do nothing
            # Same thing if it's currently None and we set it to None, [], or {}
            if self.data[key] == v or (self.data[key] is None and v in (None, [], {})):
                return v
            else:
                # Used for passing upward to the parent profile
                initial_value = copy(self.data[key])

                self.data[key] = v

            # No need to sign things that don't have a signature (this shouldn't happen)
            if "signature" not in self.data:
                return v

            # Update the creation and modified times
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            if self.data["metadata"]["created"][0:4] == "1970":
                self.data["metadata"]["created"] = timestamp
            self.data["metadata"]["last_modified"] = timestamp

            # if the display level hasn't already been set, set it to the global value
            if self.data["metadata"]["display"] is None and DISPLAY_LEVEL is not None:
                self.data["metadata"]["display"] = DISPLAY_LEVEL
            elif self.data["metadata"]["display"] is None and DISPLAY_LEVEL is None:
                raise ValueError("Attempted to sign attribute without selecting display level")

            # Now let's actually sign things I guess. ¯\_(ツ)_/¯
            if PUBLISHER_SIGNING_KEY is None:
                raise RuntimeError("Unable to load signing key")

            del self.data["signature"]
            self.data["signature"] = {
                "additional": [{
                    "alg": "RS256",
                    "name": None,
                    "typ": "JWS",
                    "value": "",
                }],
                "publisher": {
                    "alg": "RS256",
                    "name": environ["PUBLISHER_NAME"],
                    "typ": "JWS",
                    "value": jws.sign(self.data, PUBLISHER_SIGNING_KEY, algorithm="RS256"),
                }
            }

            # Tell the parent profile that this attribute has changed, making it nice for lists
            # There is probably a better way of doing this
            if self._is_list(initial_value) and self._is_list(v):
                adding = sorted(set(v.keys()).difference(set(initial_value.keys())))
                deleting = sorted(set(initial_value.keys()).difference(set(v.keys())))

                adding = ", ".join([f"+{i}" for i in adding])
                deleting = ", ".join([f"-{i}" for i in deleting])

                self.__parent_profile.notify(self.__name,
                                             f"{adding}, {deleting}" if adding and deleting else f"{adding}{deleting}")
            elif initial_value is None and self._is_list(v):
                adding = ", ".join([f"+{i}" for i in sorted(v.keys())])

                self.__parent_profile.notify(self.__name, adding)
            else:
                self.__parent_profile.notify(self.__name, f"{initial_value} --> {v}")

        else:
            super().__setattr__(k, v)

        return v

    def _is_list(self, thingy) -> bool:
        return isinstance(thingy, dict) and not any(list(thingy.values()))
