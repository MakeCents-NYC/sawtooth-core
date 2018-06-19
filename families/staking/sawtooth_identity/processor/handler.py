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

import logging
import hashlib


from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.messaging.future import FutureTimeoutError
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.protobuf.setting_pb2 import Setting

from sawtooth_identity.protobuf.block_info_pb2 import BlockInfoConfig

from sawtooth_identity.protobuf.stake_pb2 import Stake
from sawtooth_identity.protobuf.stake_pb2 import StakeList
from sawtooth_identity.protobuf.stake_payload_pb2 import StakePayload
from sawtooth_identity.protobuf.stake_payload_pb2 import MintStakeTransactionData
from sawtooth_identity.protobuf.stake_payload_pb2 import SendStakeTransactionData
from sawtooth_identity.protobuf.stake_payload_pb2 import LockStakeTransactionData

LOGGER = logging.getLogger(__name__)

# The identity namespace is special: it is not derived from a hash.
STAKE_NAMESPACE = '807062'
_DEFAULT_TYPE_PREFIX = '00'
_ADDRESS_PART_SIZE = 62


def _stake_to_address(owner_pub):
    addr_part = _to_hash(owner_pub)[:_ADDRESS_PART_SIZE]
    return STAKE_NAMESPACE + _DEFAULT_TYPE_PREFIX + addr_part

# Constants to be used when constructing config namespace addresses
_SETTING_NAMESPACE = '000000'
_SETTING_MAX_KEY_PARTS = 4
_SETTING_ADDRESS_PART_SIZE = 16
# Number of seconds to wait for state operations to succeed
STATE_TIMEOUT_SEC = 10


def _setting_key_to_address(key):
    """Computes the address for the given setting key.

     Keys are broken into four parts, based on the dots in the string. For
     example, the key `a.b.c` address is computed based on `a`, `b`, `c` and
     padding. A longer key, for example `a.b.c.d.e`, is still
     broken into four parts, but the remaining pieces are in the last part:
     `a`, `b`, `c` and `d.e`.

     Each of these pieces has a short hash computed (the first
     _SETTING_ADDRESS_PART_SIZE characters of its SHA256 hash in hex), and is
     joined into a single address, with the config namespace
     (_SETTING_NAMESPACE) added at the beginning.

     Args:
         key (str): the setting key
     Returns:
         str: the computed address
     """
    # Split the key into _SETTING_MAX_KEY_PARTS parts, maximum, compute the
    # short hash of each, and then pad if necessary
    key_parts = key.split('.', maxsplit=_SETTING_MAX_KEY_PARTS - 1)
    addr_parts = [_setting_short_hash(byte_str=x.encode()) for x in key_parts]
    addr_parts.extend(
        [_SETTING_ADDRESS_PADDING] * (_SETTING_MAX_KEY_PARTS - len(addr_parts))
    )
    return _SETTING_NAMESPACE + ''.join(addr_parts)


def _setting_short_hash(byte_str):
    # Computes the SHA 256 hash and truncates to be the length
    # of an address part (see _config_key_to_address for information on
    return hashlib.sha256(byte_str).hexdigest()[:_SETTING_ADDRESS_PART_SIZE]


_SETTING_ADDRESS_PADDING = _setting_short_hash(byte_str=b'')
ALLOWED_SIGNER_ADDRESS = _setting_key_to_address(
    "sawtooth.stake.allowed_keys")

NAMESPACE = '00b10c'
BLOCK_INFO_NAMESPACE = NAMESPACE + '00'
BLOCK_CONFIG_ADDRESS = NAMESPACE + '01' + '0' * 62


def create_block_address(block_num):
    return BLOCK_INFO_NAMESPACE + hex(block_num)[2:].zfill(62)


def _check_block_number(block_config_data, context):

    block_config = _get_data(BLOCK_CONFIG_ADDRESS, context)
    if not block_config:
        raise InvalidTransaction(
            "There doesn't appear to be a block_config stored here."
            " Are you sure there is a block_info" 
            " transaction processor component configured?")

    block_config = BlockInfoConfig()
    block_config.ParseFromString()
    return block_config.latest_block


def _check_allowed_minter(minting_key, context):
    entries_list = _get_data(ALLOWED_SIGNER_ADDRESS, context)
    if not entries_list:
        raise InvalidTransaction(
            "The transaction signer is not authorized to submit transactions: "
            "{}".format(minting_key))

    setting = Setting()
    setting.ParseFromString(entries_list[0].data)
    for entry in setting.entries:
        if entry.key == "sawtooth.stake.allowed_keys":
            allowed_signer = entry.value.split(",")
            if minting_key in allowed_signer:
                return

    raise InvalidTransaction(
        "The transction signer is not authorized mint stake tokens: "
        "{}".format(minting_key))


class IdentityTransactionHandler(TransactionHandler):
    @property
    def family_name(self):
        return 'stake'

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [STAKE_NAMESPACE]

    def apply(self, transaction, context):
        header = transaction.header
        signer = header.signer_public_key
        # parse the payload
        payload = StakePayload()
        payload.ParseFromString(transaction.payload)

        id_type = payload.payload_type

        if id_type == StakePayload.SEND_STAKE:
            _set_send(payload.send, context)

        elif id_type == StakePayload.LOCK_STAKE:
            _set_lock(payload.lock, context)

        elif id_type == StakePayload.MINT_STAKE:
            _apply_mint(payload.mint, context, signer)

        else:
            raise InvalidTransaction("The StakeType must be either a"
                                     " MINT, SEND, or LOCK payload")


def _apply_mint(minting_payload, context, public_key):
    """
    The _set_mint function is used to initialize the staking tp.
    It requires that a public key be set in the transaction
    procesor settings under the settings.stake.mint.key
    :param data: The deserialized MintStakeTransactionData protobuf
    :param context: The connection information to the validator
    :return: ok
    """
    _check_allowed_minter(public_key, context)
    total_supply = minting_payload.totalSupply

    stake_list = StakeList()
    stake_list.stakeMap.get_or_create(public_key)

    stake_list.stakeMap[public_key].nonce = 1
    stake_list.stakeMap[public_key].ownerPubKey = public_key
    stake_list.stakeMap[public_key].value = total_supply
    stake_list.stakeMap[public_key].value = 1

    # calculate the address to write to
    address = _stake_to_address(public_key)

    # submit the state to update to the validator
    ico_data = {address: stake_list.SerializeToString()}
    _set_data(context, **ico_data)


def _set_send(data, context):
    raise NotImplementedError()


def _set_lock(data, context):
    raise NotImplementedError


def _set_data(context, **address_dict):
    """
    This function is used to set state by submitting requests to the validator.
    :arg context: The connection information with the validaor
    :arg address_dict: a dictionary of state addresses to be updated where the
        keys are the addressess and the value is the serialized protobuf data.
    """
    try:
        context.set_state(address_dict, timeout=STATE_TIMEOUT_SEC)
    except FutureTimeoutError:
        LOGGER.warning('Timeout occured on context.set_state({}').format(address_dict)
        raise InternalError('Unable to set {}').format(address_dict)


def _get_data(address, context):
    try:
        entries_list = context.get_state([address], timeout=STATE_TIMEOUT_SEC)

    except FutureTimeoutError:
        LOGGER.warning('Timeout occured on context.get_state([%s])', address)
        raise InternalError('Unable to get {}'.format(address))

    return entries_list


def _to_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()





