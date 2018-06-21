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

# from sawtooth_identity.protobuf.identity_pb2 import Policy
# from sawtooth_identity.protobuf.identity_pb2 import PolicyList
# from sawtooth_identity.protobuf.identity_pb2 import Role
# from sawtooth_identity.protobuf.identity_pb2 import RoleList
# from sawtooth_identity.protobuf.identities_pb2 import IdentityPayload

from sawtooth_block_info.protobuf.block_info_pb2 import BlockInfoTxn
from sawtooth_block_info.protobuf.block_info_pb2 import BlockInfo
from sawtooth_block_info.protobuf.block_info_pb2 import BlockInfoConfig

from makecents-stake.protobuf.stake_pb2 import Stake
from makecents-stake.protobuf.stake_pb2 import StakeList
from makecents-stake.protobuf.stake_payload_pb2 import StakePayload
from makecents-stake.protobuf.block_info_pb2 import BlockInfoConfig

LOGGER = logging.getLogger(__name__)

# The identity namespace is special: it is not derived from a hash.
STAKE_NAMESPACE = '807062'
_DEFAULT_TYPE_PREFIX = '00'
flag=0

# Constants to be used when constructing config namespace addresses
_SETTING_NAMESPACE = '000000'
_SETTING_MAX_KEY_PARTS = 2
_SETTING_ADDRESS_PART_SIZE = 62
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
    "sawtooth.identity.allowed_keys")



class StakeTransactionHandler(TransactionHandler):
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

        if _check_valid_signer(transaction, context):
            header=transaction.header
            ownerPubKey=header.signer_public_key
            payload = StakePayload()
            payload.ParseFromString(transaction.payload)
            id_type = payload.PayloadType
            sender_stake = _get_stake(ownerPubKey)
            #GET Block Info
            address=_stake_to_address(ownerPubKey)
            current_block=get_block(address,context)
            current_block.parseFromString(transaction.payload)
            if sender_stake is None:
                return
            else:
                if id_type == StakePayload.SEND:
                    send=payload.send
                    #send=StakePayload.SendStakeTransactionData()
                    #send.parseFromString(payload.data)
                    _send_stake(send,context,sender_stake,current_block)
                elif id_type == StakePayload.LOCK:
                    lock=payload.lock
                    #lock=StakePayload.LockStakeTransactionData()
                    #lock.parseFromString(payload.data)
                    #_lock_stake(lock,context)
                else:
                    raise InvalidTransaction("The StakeType must be either a SEND or LOCK payload")
        else:
            return



def get_block(address,context):
    entries=context.get_state([address])
    if not entries:
        return
    else:
        current_block=BlockInfoConfig()
        current_block.parseFromString(entries[0].data)
        return current_block


def _check_valid_signer(transaction, context):
    header = transaction.header
    entries_list = _get_data(ALLOWED_SIGNER_ADDRESS, context)
    if not entries_list:
        raise InvalidTransaction(
            "The transaction signer is not authorized to submit transactions: "
            "{}".format(header.signer_public_key))
    return


def _get_stake(pub_key,context):
    address=_stake_to_address(pub_key)
    entries=context.get_state([address])
    if not entries:
        return
    else:
        stake_list=StakePayload()
        stake_list.ParseFromString(entries[0].data)
        stake=Stake()
        stake.parseFromString(stake_list.get(pub_key))
        if stake is None:
            return
        else:
            return stake



def _send_stake(send, context,sender_stake,current_block):
    if send.toPubKey is None:
        raise InvalidTransaction("Every stake transaction entry must have ownerPubkey.")
    if send.value is None:
        raise InvalidTransaction("Every stake transaction must have a value.")
    if sender_stake.blockNumber < current_block.latest_block:
        raise InvalidTransaction("Invalid Block Number")
    if send.value > sender_stake.value:
        raise InvalidTransaction("Insufficient Balance")
    receiver_stake=_get_stake(send.toPubKey,context)
    senderstake_list=get_stakelist(sender_stake.ownerPubKey,context)
    receiverstake_list=get_stakelist(send.toPubKey,context)
    if receiver_stake is None:
        receiver_stake=_create_stake(send,current_block)
    else:
        if locked(sender_stake,current_block) or locked(receiver_stake):
            raise InvalidTransaction("Transaction stake is locked")
        else:
            sender_stake=_update_stake(sender_stake,'sender',send.value)
            receiver_stake=_update_stake(receiver_stake,'receiver',send.value)
    senderstake_list[sender_stake.ownerPubKey]=sender_stake
    senderstake_list[receiver_stake.ownerPubKey]=receiver_stake
    receiverstake_list[sender_stake.ownerPubKey] = sender_stake
    receiverstake_list[receiver_stake.ownerPubKey]=receiver_stake
    senderstake_list.SerializeToString()
    _set_stake(context,senderstake_list)
    _set_stake(context,receiverstake_list)

def locked(stake,current_block):

    if stake.blockNumber > current_block.latest_block:
        raise InvalidTransaction("")
    else:
        return
def get_stakelist(pub_key,context):
    address=_stake_to_address(pub_key)
    entries=context.get_state(address)
    if not entries:
        return
    else:
        stake_list=StakeList()
        stake_list.parseFromString(entries[0].data)
    return stake_list

def _update_stake(stake,stype,tvalue):
    if stype=='sender':
        stake.value=stake.value-tvalue
    elif stype=='receiver':
        stake.value=stake.value+tvalue
    stake.SerializeToString()
    return stake

def _create_stake(send,current_block):
    #creating a new Stake from a send object
    stakelist=StakeList()
    public_key=send.toPubKey
    stakelist.stakeMap[public_key].nonce = 1
    stakelist.stakeMap[public_key].ownerPubKey = public_key
    stakelist.stakeMap[public_key].value = send.value
    stakelist.stakeMap[public_key].blockNumber=current_block.latest_block+1
    stakelist.SerializeToString()
    #
    # new_stake=Stake()
    # new_stake.nonce=1
    # new_stake.ownerPubKey=send.toPubKey
    # new_stake.value=send.value
    # new_stake.blockNumber=current_block.latest_block+1
    # new_stake.SerializeToString()
    # return new_stake
    return stakelist

def _set_stake(context,stake_list):
    #Stake_list is a list of stakes that are to be updated
    addresses=[]
    for stake in stake_list:
        stake.SerializeToString()
        stk_address=_stake_to_address(stake.ownerPubKey)
        addresses.append(stk_address)
    context.set_state(addresses)
    return



def _lock_stake(lock, context):
    raise InvalidTransaction("The name must be set in a role")

 # TODO refactor into key_to_address for clarity
def _stake_to_address(self, owner_pub):
        addr_part = self._to_hash(owner_pub)[:_ADDRESS_PART_SIZE]
        return self._factory.namespace + _DEFAULT_TYPE_PREFIX + addr_part

def _get_data(address, context):
    try:
        entries_list = context.get_state([address], timeout=STATE_TIMEOUT_SEC)

    except FutureTimeoutError:
        LOGGER.warning('Timeout occured on context.get_state([%s])', address)
        raise InternalError('Unable to get {}'.format(address))

    return entries_list


def _to_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _get_policy_address(policy_name):
    return IDENTITY_NAMESPACE + POLICY_PREFIX + _to_hash(policy_name)[:62]


_MAX_KEY_PARTS = 4
_FIRST_ADDRESS_PART_SIZE = 14
_ADDRESS_PART_SIZE = 16
_EMPTY_PART = _to_hash('')[:_ADDRESS_PART_SIZE]


def _get_role_address(role_name):
    # split the key into 4 parts, maximum
    key_parts = role_name.split('.', maxsplit=_MAX_KEY_PARTS - 1)

    # compute the short hash of each part
    addr_parts = [_to_hash(key_parts[0])[:_FIRST_ADDRESS_PART_SIZE]]
    addr_parts += [_to_hash(x)[:_ADDRESS_PART_SIZE] for x in key_parts[1:]]

    # pad the parts with the empty hash, if needed
    addr_parts.extend([_EMPTY_PART] * (_MAX_KEY_PARTS - len(addr_parts)))

    return IDENTITY_NAMESPACE + ROLE_PREFIX + ''.join(addr_parts)
