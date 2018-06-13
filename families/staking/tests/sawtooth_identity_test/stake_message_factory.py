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

from sawtooth_identity.protobuf.setting_pb2 import Setting

_MAX_KEY_PARTS = 2
_STAKE_TYPE_SIZE = 2
_ADDRESS_PART_SIZE = 62

_DEFAULT_TYPE_PREFIX = '00'

LOGGER = logging.getLogger(__name__)


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
        if payload.type == StakePayload.SEND:
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
        else:
            lock = LockStakeTransactionData()
            lock.ParseFromString(payload.data)

            inputs = [self._stake_to_address(self._factory.get_public_key())]

            outputs = [self._stake_to_address(self._factory.get_public_key())]

        return self._factory.create_tp_process_request(
            payload.SerializeToString(), inputs, outputs, [])

    def create_send_stake_transaction(self, to_public_key, stake_amount):
        send = SendStakeTransactionData(toPubKey=to_public_key,
                                        amount=stake_amount)

        payload = StakePayload(payload_type=StakePayload.SEND,
                               data=send.SerializeToString())

        return self._create_tp_process_request(payload)

    def create_lock_stake_transaction(self, block_number):
        lock = LockStakeTransactionData(blockNumber=block_number)
        payload = StakePayload(payload_type=StakePayload.LOCK,
                               data=lock.SerializeToString())
        return self._create_tp_process_request(payload)

    def create_get_stake_request(self, public_key):
        addresses = [self._stake_to_address(public_key)]
        # TODO. parse the entries?
        return self._factory.create_get_request(addresses)

    def create_get_stake_response(self, pub_key, map=None):
        address = self._stake_to_address(pub_key)
        if map is not None:
            stake = map[pub_key]  # this should be a Stake type, since the map is from pub_key -> stake
            data = stake.SerializeToString()  # marshall it
        else:
            data = None
        return self._factory.create_get_response({address: data})

    def create_get_lock_info_request(self, pub_key):
        pass

    def create_get_lock_info_response(self, pub_key, config=None):
        pass

    def create_set_stake_request(self, to_pub_key, amount=None):
        # there is a lot more to do here, we need to create someway to update
        # only specifc stake amounts int he presence of a map.
        pass

    def create_set_stake_response(self, name):
        pass

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
                key="sawtooth.identity.allowed_keys",
                value=self.public_key)
            data = Setting(entries=[entry]).SerializeToString()
        else:
            entry = Setting.Entry(
                key="sawtooth.identity.allowed_keys",
                value="")
            data = Setting(entries=[entry]).SerializeToString()

        return self._factory.create_get_response({key: data})

    def create_add_event_request(self, key):
        return self._factory.create_add_event_request(
            "stake/update",
            [("updated", key)])

    def create_add_event_response(self):
        return self._factory.create_add_event_response()
