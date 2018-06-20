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
import logging
from sawtooth_processor_test.message_factory import MessageFactory
from sawtooth_identity.protobuf.block_info_pb2 import BlockInfo
from sawtooth_identity.protobuf.stake_pb2 import Stake
from sawtooth_identity.protobuf.stake_pb2 import StakeList
from sawtooth_identity.protobuf.stake_payload_pb2 import StakePayload
from sawtooth_identity.protobuf.stake_payload_pb2 import LockStakeTransactionData
from sawtooth_identity.protobuf.stake_payload_pb2 import SendStakeTransactionData
from sawtooth_identity.protobuf.stake_payload_pb2 import MintStakeTransactionData

from sawtooth_identity.protobuf.block_info_pb2 import BlockInfoConfig

from sawtooth_identity.protobuf.setting_pb2 import Setting

_MAX_KEY_PARTS = 2
_STAKE_TYPE_SIZE = 2
_ADDRESS_PART_SIZE = 62
_DEFAULT_TYPE_PREFIX = '00'

LOGGER = logging.getLogger(__name__)

CONFIG_ADDRESS = '00b10c' + '01' + '0' * 62
DEFAULT_SYNC_TOLERANCE = 60 * 5
DEFAULT_TARGET_COUNT = 256


class StakeMessageFactory(object):
    def __init__(self, signer=None):
        self._factory = MessageFactory(
            family_name="stake",
            family_version="1.0",
            namespace="807062",
            signer=signer,
        )

    @property
    def public_key(self):
        return self._factory.get_public_key()

    def _to_hash(self, value):
        return hashlib.sha256(value.encode()).hexdigest()

    # TODO refactor into key_to_address for clarity
    def _stake_to_address(self, owner_pub):
        addr_part = self._to_hash(owner_pub)[:_ADDRESS_PART_SIZE]
        return self._factory.namespace + _DEFAULT_TYPE_PREFIX + addr_part

    def create_tp_register(self):
        return self._factory.create_tp_register()

    def create_tp_response(self, status):
        return self._factory.create_tp_response(status)

    def _create_tp_process_request(self, payload):
        inputs = []
        outputs = []
        if payload.payload_type == StakePayload.SEND_STAKE:
            send = SendStakeTransactionData()
            send.ParseFromString(payload.data)
            #TODO add block_info
            inputs = [
                # the stake address `from`
                self._stake_to_address(self._factory.get_public_key()),
                # the stake address `to`
                self._stake_to_address(send.toPubKey)
            ]
            outputs = [
                # the stake address `from`
                self._stake_to_address(self._factory.get_public_key()),
                # the stake address `to`
                self._stake_to_address(send.toPubKey)
            ]
        elif payload.payload_type == StakePayload.LOCK_STAKE:
            lock = payload.lock
            inputs = [self._stake_to_address(self._factory.get_public_key())]
            outputs = [self._stake_to_address(self._factory.get_public_key())]

        # MINT_STAKE
        else:
            # Extract the payload from create_mint_stake_transaction, will need to extract
            # the pub keys for ICO
            mint = payload.mint
            inputs = [self._stake_to_address(self._factory.get_public_key())]
            outputs = [self._stake_to_address(self._factory.get_public_key())]

        return self._factory.create_tp_process_request(
            payload.SerializeToString(), inputs, outputs, [])

    def create_mint_stake_transaction(self, total_supply: float, mint_key: str):
        mint = MintStakeTransactionData()
        mint.totalSupply = total_supply
        mint.ico[mint_key] = total_supply

        payload = StakePayload(payload_type=StakePayload.MINT_STAKE,
                               mint=mint)
        return self._create_tp_process_request(payload)

    def create_lock_stake_transaction(self, block_number: int):
        lock = LockStakeTransactionData()
        lock.blockNumber = block_number

        payload = StakePayload(payload_type=StakePayload.LOCK_STAKE,
                               lock=lock)
        return self._create_tp_process_request(payload)

    def create_mint_stake_request(self, total_supply, public_key):
        stake_list = StakeList()
        # create the unreferenced key
        stake_list.stakeMap.get_or_create(public_key)
        # assign each submessage field indirectly
        stake_list.stakeMap[public_key].nonce = 1
        stake_list.stakeMap[public_key].ownerPubKey = public_key
        stake_list.stakeMap[public_key].value = total_supply
        stake_list.stakeMap[public_key].blockNumber = 1
        return self._factory.create_set_request({
            self._stake_to_address(public_key): stake_list.SerializeToString()})

    def create_mint_stake_response(self, key):
        stake_addr = [self._stake_to_address(key)]
        return self._factory.create_set_response(stake_addr)

    def create_set_stake_request(self, public_key, stake=None):
        stake_list = self.create_stake(stake=stake)
        return self._factory.create_set_request({
            self._stake_to_address(public_key): stake_list.SerializeToString()})

    def create_set_stake_response(self, public_key):
        addresses = [self._stake_to_address(public_key)]
        return self._factory.create_set_response(addresses)

    def create_get_stake_request(self, public_key):
        addresses = [self._stake_to_address(public_key)]
        return self._factory.create_get_request(addresses)

    def create_get_stake_response(self, pub_key, stake=None):
        data = None
        if stake is not None:
                data = self.create_stake(stake=stake)
        return self._factory.create_get_response(
            {self._stake_to_address(pub_key): data.SerializeToString()})

    def create_set_lock_request(self, name, policy_name):
        pass

    def create_set_lock_response(self, name):
        pass

    def create_get_setting_request(self, key):
        addresses = [key]
        return self._factory.create_get_request(addresses)

    def create_get_setting_response(self, key, allowed):
        if allowed:
            entry = Setting.Entry(
                key="sawtooth.stake.allowed_keys",
                value=self.public_key)
            data = Setting(entries=[entry]).SerializeToString()
        else:
            entry = Setting.Entry(
                key="sawtooth.stake.allowed_keys",
                value="")
            data = Setting(entries=[entry]).SerializeToString()

        return self._factory.create_get_response({key: data})

    def create_add_event_request(self, key):
        return self._factory.create_add_event_request(
            "stake/update",
            [("updated", key)])

    def create_add_event_response(self):
        return self._factory.create_add_event_response()

    def create_config(self,
                      latest_block,
                      oldest_block=None,
                      target_count=DEFAULT_TARGET_COUNT,
                      sync_tolerance=DEFAULT_SYNC_TOLERANCE):
        if oldest_block is None:
            oldest_block = latest_block - DEFAULT_TARGET_COUNT
        return BlockInfoConfig(
            latest_block=latest_block,
            oldest_block=oldest_block,
            target_count=target_count,
            sync_tolerance=sync_tolerance)

    def create_stake(self,
                     owner_key=None,
                     value=None,
                     block_number=None,
                     nonce=None,
                     stake=None):
        # if there is already a stake list
        if stake is not None:
            return stake
        # there is no state at the address.
        else:
            stake_list = StakeList()
            stake_list.stakeMap.get_or_create(owner_key)
            stake_list.stakeMap[owner_key].ownerPubKey = owner_key
            stake_list.stakeMap[owner_key].nonce = nonce
            stake_list.stakeMap[owner_key].blockNumber = block_number
            stake_list.stakeMap[owner_key].value = value
            return stake_list

    def create_get_block_config_request(self):
        return self._factory.create_get_request(addresses=[CONFIG_ADDRESS])

    def create_get_block_config_response(self, config):
        if config:
            LOGGER.info(config)
            data = self.create_config(2, oldest_block=1)
            #conf = self.create_config(config.latest_block, oldest_block=1)
            #data = config.SerializeToString()
        else:
            data = None
        return self._factory.create_get_response({CONFIG_ADDRESS: data.SerializeToString()})



    # def create_send_stake_transaction(self, to_public_key, stake_amount):
    #     send = SendStakeTransactionData(toPubKey=to_public_key,
    #                                     amount=stake_amount)
    #
    #     payload = StakePayload(payload_type=StakePayload.SEND,
    #                            data=send.SerializeToString())
    #
    #     return self._create_tp_process_request(payload)
    #
    # def create_lock_stake_transaction(self, block_number):
    #     lock = LockStakeTransactionData(blockNumber=block_number)
    #     payload = StakePayload(payload_type=StakePayload.LOCK,
    #                            data=lock.SerializeToString())
    #     return self._create_tp_process_request(payload)
    #
    # def create_get_lock_stake_request(self, pub_key):
    #     pass
    #
    # def create_get_lock_stake_response(self, pub_key, config=None):
    #     pass
