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

from makecents_cash.protobuf.block_info_pb2 import BlockInfoConfig

from makecents_cash.protobuf.stake_pb2 import Stake
from makecents_cash.protobuf.stake_pb2 import StakeList
from makecents_cash.protobuf.stake_payload_pb2 import StakePayload
from makecents_cash.protobuf.stake_payload_pb2 import MintStakeTransactionData
from makecents_cash.protobuf.stake_payload_pb2 import SendStakeTransactionData
from makecents_cash.protobuf.stake_payload_pb2 import LockStakeTransactionData

LOGGER = logging.getLogger(__name__)

# sha512('cash'.encode('utf-8')).hexdump[:6]
CASH_NAMESPACE = '3b905b'
_DEFAULT_TYPE_PREFIX = '00'
_ADDRESS_PART_SIZE = 62


def _cash_to_address(owner_id):
    addr_part = _to_hash(owner_id)[:_ADDRESS_PART_SIZE]
    return CASH_NAMESPACE + _DEFAULT_TYPE_PREFIX + addr_part

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


def _check_allowed_minter(minting_key, context):
    entries_list = _get_data(ALLOWED_SIGNER_ADDRESS, context)
    if not entries_list:
        raise InvalidTransaction(
            "The transaction signer is not authorized to submit transactions: "
            "{}".format(minting_key))

    setting = Setting()
    setting.ParseFromString(entries_list[0].data)
    for entry in setting.entries:
        if entry.key == "makecents.cash.allowed_keys":
            allowed_signer = entry.value.split(",")
            LOGGER.info('minting key: {}'.format(allowed_signer))
            if minting_key == allowed_signer[0]:
                return

    raise InvalidTransaction(
        "The transction signer is not authorized mint stake tokens: "
        "{}".format(minting_key))


def _check_allowed_signer(signing_key, stake_owner):
    if signing_key == stake_owner:
        return
    raise InvalidTransaction(
        "The signer of this transaction is not authorized to modify this stake")


def _check_allowed_lock(current_block, current_lock, target_lock_block):
    if target_lock_block < current_block:
        raise InvalidTransaction("Cannot lock stake in the past. "
                                 "\n current block number: {} "
                                 "\n target lock block: {}."
                                 .format(current_block, target_lock_block))

    if current_lock > current_block:
        raise InvalidTransaction("Cannot lock stake that is already locked. "
                                 "\n current block number: {} "
                                 "\n current lock block: {}."
                                 .format(current_block, current_lock))
    return

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
            _apply_send(payload.send, context, signer)

        elif id_type == StakePayload.LOCK_STAKE:
            _apply_lock(payload.lock, context, signer)

        elif id_type == StakePayload.MINT_STAKE:
            _apply_mint(payload.mint, context, signer)

        else:
            raise InvalidTransaction("The StakeType must be either a"
                                     " MINT, SEND, or LOCK payload")


def _build_stake_list(stake, stake_list=None):
    """
    This is a utility function for constructing stake lists
    as well as updating existing ones while preserving state.
    :param stake: Stake_pb2
    :param stake_list: StakeList_pb2
    :return: StakeList_pb2 updated with new stake element.
    """
    #TODO(): type check.
    raise NotImplementedError


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
    current_block = _check_block_number(context)
    LOGGER.info('The current block is :{}'.format(current_block))
    if current_block != 1 :
        raise InvalidTransaction("Minting stake after the genesis block is forbidden.")
    total_supply = minting_payload.totalSupply

    stake_list = StakeList()
    stake_list.stakeMap.get_or_create(public_key)

    #
    stake_list.stakeMap[public_key].nonce = 1
    stake_list.stakeMap[public_key].ownerPubKey = public_key
    stake_list.stakeMap[public_key].value = total_supply
    stake_list.stakeMap[public_key].blockNumber = current_block
    # calculate the address to write to
    address = _stake_to_address(public_key)

    # submit the state to update to the validator
    ico_data = {address: stake_list.SerializeToString()}
    _set_data(context, **ico_data)

    context.add_event(
        event_type="stake/update", attributes=[("updated", public_key)])
    LOGGER.debug("Updated address: \n {}".format(public_key))


def _apply_send(data, context, public_key):
    owner_address = _stake_to_address(public_key)
    # 1st get
    owner_sl = _get_data(owner_address, context)
    if not owner_sl:
        raise InvalidTransaction(
            "There doesn't appear to be any stake here.")
    # parse the payload
    sender_stake_list = StakeList()
    sender_stake_list.ParseFromString(owner_sl[0].data)
    sender_stake = sender_stake_list.stakeMap.get_or_create(public_key)
    # Is this sufficient?
    if not sender_stake_list.stakeMap[public_key]:
        raise InvalidTransaction("The signer of this transaction "
                                 "does not own any stake")
    # ensure the signer is allowed to do this.
    _check_allowed_signer(sender_stake.ownerPubKey, public_key)

    # second get
    # get the block number to make sure this is not locked.
    current_block = _check_block_number(context)  # the most recent block

    # Is this sufficient?
    if not sender_stake_list.stakeMap[public_key]:
        raise InvalidTransaction("The signer of this transaction "
                                 "does not own any stake")

    # check if the sender stake is locked
    if sender_stake.blockNumber > current_block:
        raise InvalidTransaction("The stake at {} is locked".format(public_key))

    # get the receiver stake
    receiver_address = _stake_to_address(data.toPubKey)
    receiver_sl = _get_data(receiver_address, context)
    receiver_stake_list = StakeList()
    receiver_stake_list.ParseFromString(receiver_sl[0].data)
    receiver_stake = receiver_stake_list.stakeMap.get_or_create(data.toPubKey)

    if receiver_stake.blockNumber > current_block:
        raise InvalidTransaction("The stake at {} is locked".format(data.toPubKey))
    # business logic
    if data.value is 0:
        raise InvalidTransaction("Zero amount transactions are forbidden")
    if data.value > sender_stake.value:
        raise InvalidTransaction("Insufficient Balance")

    # Everything checks out, build the updated states
    # Start with receiver
    receiver_stake_list.stakeMap[data.toPubKey].nonce += 1
    receiver_stake_list.stakeMap[data.toPubKey].value += data.value

    # Then sender
    sender_stake_list.stakeMap[public_key].nonce += 1
    sender_stake_list.stakeMap[public_key].value -= data.value

    # serialize and build the dictionary
    send_stake = {
        owner_address: sender_stake_list.SerializeToString()
    }

    receive_stake = {
        receiver_address: receiver_stake_list.SerializeToString(),
    }

    # send
    _set_data(context, **send_stake)

    context.add_event(
        event_type="stake/update", attributes=[("updated", public_key)])
    LOGGER.debug("Updated address: \n {}".format(public_key))

    # receive
    _set_data(context, **receive_stake)

    context.add_event(
        event_type="stake/update", attributes=[("updated", data.toPubKey)])
    LOGGER.debug("Updated address: \n {}".format(data.toPubKey))


def _apply_lock(data, context, public_key):
    """
    The _set_mint function is used to initialize the staking tp.
    It requires that a public key be set in the transaction
    procesor settings under the settings.stake.mint.key
    :param data: The deserialized MintStakeTransactionData protobuf
    :param context: The connection information to the validator
    :return: ok
    """
    owner_address = _stake_to_address(public_key)
    owner_sl = _get_data(owner_address, context)
    if not owner_sl:
        raise InvalidTransaction(
            "There doesn't appear to be any stake here.")
    # parse the payload
    stake_list = StakeList()
    stake_list.ParseFromString(owner_sl[0].data)
    stake = stake_list.stakeMap.get_or_create(public_key)
    # Is this sufficient?
    if not stake_list.stakeMap[public_key]:
        raise InvalidTransaction("The signer of this transaction "
                                 "does not own any stake")
    # ensure the signer is allowed to do this.
    _check_allowed_signer(stake.ownerPubKey, public_key)

    current_lock = stake.blockNumber  #
    current_block = _check_block_number(context)  # the most recent block
    target_lock_block = data.blockNumber  # The block we want to lock until

    _check_allowed_lock(current_block, current_lock, target_lock_block)

    # increment the nonce
    stake_list.stakeMap[public_key].nonce += 1
    # set the locks
    stake_list.stakeMap[public_key].blockNumber = target_lock_block

    # submit the state to update to the validator
    lock_data = {owner_address: stake_list.SerializeToString()}
    _set_data(context, **lock_data)

    context.add_event(
        event_type="stake/update", attributes=[("updated", public_key)])
    LOGGER.debug("Updated address: \n {}".format(public_key))


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
        LOGGER.warning('Timeout occured on context.set_state({}'.format(address_dict))
        raise InternalError('Unable to set {}'.format(address_dict))


def _get_data(address, context):
    try:
        entries_list = context.get_state([address], timeout=STATE_TIMEOUT_SEC)

    except FutureTimeoutError:
        LOGGER.warning('Timeout occured on context.get_state([%s])', address)
        raise InternalError('Unable to get {}'.format(address))

    return entries_list


def _to_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()





