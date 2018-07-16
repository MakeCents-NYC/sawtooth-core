# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import hashlib
from functools import lru_cache

# from sawtooth_validator.protobuf.stake_pb2 import StakeList
# from sawtooth_validator.protobuf.stake_pb2 import Stake

from stake.protobuf.stake_pb2 import StakeList
from stake.protobuf.stake_pb2 import Stake

from sawtooth_validator.state.settings_view import SettingsView

# The identity namespace is special: it is not derived from a hash.
STAKE_NAMESPACE = '807062'
_DEFAULT_TYPE_PREFIX = '00'
_ADDRESS_PART_SIZE = 62


def _to_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _check_allowed_signer(signing_key, stake_owner):
    if signing_key == stake_owner:
        # TODO: maybe we should assert here?
        return
    raise Exception(
        "This is not the owner of the stake")


class StakeView(object):
    """
    A StakeView provides access to on-chain configuration stake.

    The Config view provides access to configuration stake stored at a
    particular merkle tree root. This access is read-only.
    """

    def __init__(self, state_view):
        """Creates a StakeView, given a StateView for merkle tree access.

        Args:
            state_view (:obj:`StateView`): a state view
        """
        self._state_view = state_view
        self._settings_view = SettingsView(state_view)

        # The public method for get_stake should have its results memoized
        # via an lru_cache.  Typical use of the decorator results in the
        # cache being global, which can cause views to return incorrect
        # values across state root hash boundaries.
        self.get_stake = lru_cache(maxsize=128)(self._get_stake)

    def _get_stake(self, key):
        """Get the stake stored at the given key. I
        Args:
            key (str): the stake key
        Returns:
            float: The value of stake stored at a specific state address and
            public_key
        """
        try:
            state_entry = self._state_view.get(
                StakeView.stake_address(key))
        except KeyError:
            raise Exception('State miss error, nothing there. Raise exception')

        if state_entry is not None:
            # parse the state entry (it should be a stake_list)
            sender_stake_list = StakeList()
            try:
                # There should only be one value there, the array position in because
                # the journal returns an array.
                sender_stake_list.ParseFromString(state_entry[0].data)
            except Exception():
                raise Exception('TODO: make a Protobuf Decode Error')
            sender_stake = sender_stake_list.stakeMap.get_or_create(key)
            if not sender_stake_list.stakeMap[key]:
                raise Exception('This sign_up information doesnt own any stake here')
            # ensure the signer is allowed to do this.
            if _check_allowed_signer(sender_stake.ownerPubKey, key):
                return sender_stake.value
        # return the value stored there.
        return None

    @staticmethod
    @lru_cache(maxsize=128)
    def stake_address(key):
        """Computes the radix address for the given stake key.
        Args:
            key (str): the stake key
        Returns:
            str: the computed address
        """
        addr_part = _to_hash(key)[:_ADDRESS_PART_SIZE]
        return STAKE_NAMESPACE + _DEFAULT_TYPE_PREFIX + addr_part


class StakeViewFactory(object):
    """Creates StakeView instances.
    """

    def __init__(self, state_view_factory):
        """Creates this view factory with a given state view factory.

        Args:
            state_view_factory (:obj:`StateViewFactory`): the state view
                factory
        """
        self._state_view_factory = state_view_factory

    def create_stake_view(self, state_root_hash):
        """
        Returns:
            StakeView: the configuration view at the given state root.
        """
        return StakeView(
            self._state_view_factory.create_view(state_root_hash))
