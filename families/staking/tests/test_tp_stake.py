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

from sawtooth_identity_test.stake_message_factory import StakeMessageFactory

from sawtooth_processor_test.transaction_processor_test_case import TransactionProcessorTestCase
from sawtooth_identity.protobuf.stake_pb2 import Stake
import secp256k1

# key_handler = secp256k1.PrivateKey()
# private_key_bytes = key_handler.private_key
# public_key_bytes = key_handler.public_key.serialize()
#
# public_key_hex = public_key_bytes.hex()
# tokey=public_key_hex



MINT_KEY_ADDRESS = '000000a87cb5eafdcca6a8f4caf4ff95731a23f91e6901b1da081ee3b0c44298fc1c14'
MINT_KEY_ADDR = '000000a87cb5eafdcca6a8f4caf4ff95731a23f91e6901b1da081ee3b0c44298fc1c20'
#tokey='0295229a6464b4e85d3d18e936405faaa1063d9d80a06fe647016cc270f659d929'


tokey='807062002c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266c1'

class TestStake(TransactionProcessorTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.factory = StakeMessageFactory()

    # expect getting a stake address
    def _expect_stake_get(self, public_key=None, **stake_alloc):
        recieved = self.validator.expect(
                self.factory.create_get_stake_request(public_key))

        self.validator.respond(
            self.factory.create_get_stake_response(public_key, stake_alloc),
                recieved)

    def _expect_stake_set(self, total_supply, public_key):
        recieved = self.validator.expect(
            self.factory.create_mint_stake_request(total_supply, public_key))

        self.validator.respond(
            self.factory.create_mint_stake_response(public_key),
            recieved)

    # creates the initial supply
    def _mint(self, total_supply, public_key):
        self.validator.send(self.factory.create_mint_stake_transaction(total_supply, public_key))

    # send a role to be created in state to validator
    def _send(self):
        self.validator.send(self.factory.create_send_stake_transaction(self._public_key,10.0,tokey))

    # send a lock command to validator
    def _lock(self, name, duration):
        pass

    def _expect_setting_get(self, key, allowed=True):
        recieved = self.validator.expect(
            self.factory.create_get_setting_request(key))

        self.validator.respond(
            self.factory.create_get_setting_response(key, allowed),
            recieved)

    def _expect_add_event(self, key):
        recieved = self.validator.expect(
            self.factory.create_add_event_request(key))

        self.validator.respond(
            self.factory.create_add_event_response(),
            recieved)

    def _expect_ok(self):
        self.validator.expect(self.factory.create_tp_response("OK"))

    def _expect_invalid_transaction(self):
        self.validator.expect(
            self.factory.create_tp_response("INVALID_TRANSACTION"))

    def _expect_internal_error(self):
        self.validator.expect(
            self.factory.create_tp_response("INTERNAL_ERROR"))

    @property
    def _public_key(self):
        return self.factory.public_key


    def test_send_stake(self):
         self._send()
         stake = Stake(nonce=1, value=1, blockNumber=1, ownerPubKey=self._public_key)
         stake_list = self.factory.build_stake_list(stake)
         self._expect_stake_get(self._public_key, **{self._public_key: stake_list})
         # # self._expect_send_stake(self._public_key,10.0,tokey)
         # # #self._expect_setting_get(MINT_KEY_ADDRESS)
         # # #self._expect_stake_set(10.0,self._public_key)
         # # #self._expect_add_event(self._public_key)
         # self._expect_ok()

    def test_mint_total_supply(self):
        """
        Tests initializing the total supply, it checks the minting
        key address to see if the signer of the transaction is correct.
        """
        self._mint(100.0, self._public_key)
        self._expect_setting_get(MINT_KEY_ADDRESS)
        self._expect_stake_set(100.0, self._public_key)
        self._expect_add_event(self._public_key)
        self._expect_ok()


    def test_mint_total_supply_with_bad_key(self):
        """
        Test that only the minting key can sign minting transaction.
        TODO: this test is superficial, we need a different signer.
        :return:
        """
        self._mint(100.0, "foo")
        self._expect_setting_get(MINT_KEY_ADDRESS, False)
        self._expect_invalid_transaction()



        # try to lock it again
        self._lock(10000)
        self._expect_stake_get(public_key=self._public_key, stake=self.factory.create_stake(owner_key=self._public_key,
                                                                                 value=1,
                                                                                 block_number=1000,
                                                                                 nonce=2))
        self._expect_config_get(config=self.factory.create_config(3, oldest_block=1))
        self._expect_invalid_transaction()

    def test_send_stake(self):
        """
        Tests sending some stake
        """
        self._send('foo', 100.0)
        # getting the sender
        self._expect_stake_get(public_key=self._public_key, stake=self.factory.create_stake(owner_key=self._public_key,
                                                                                 value=100.0,
                                                                                 block_number=1,
                                                                                 nonce=1))
        # getting the config
        self._expect_config_get(config=self.factory.create_config(100, oldest_block=1))
        # getting the receiver
        self._expect_stake_get(public_key='foo', stake=self.factory.create_stake(owner_key='foo',
                                                                                 value=100.0,
                                                                                 block_number=1,
                                                                                 nonce=1))

        # setting the sender
        self._expect_stake_set(public_key=self._public_key, stake=self.factory.create_stake(owner_key=self._public_key,
                                                               value=0,
                                                               block_number=1,
                                                               nonce=2))

        self._expect_add_event(self._public_key)


        # setting the receiver
        self._expect_stake_set(public_key='foo', stake=self.factory.create_stake(owner_key='foo',
                                                               value=200.0,
                                                               block_number=1,
                                                               nonce=2))

        self._expect_add_event('foo')


        self._expect_ok()

    def test_stake_value(self):
        """
        Testing to send value greater than the stake amount
        :return:
        """
        self._send('foo',1000.0)
        # getting the sender
        self._expect_stake_get(public_key=self._public_key,stake=self.factory.create_stake(owner_key=self._public_key,
                                                                                           value=500.0,
                                                                                           block_number=1,
                                                                                           nonce=1
                                                                                           ))
        # getting the config
        self._expect_config_get(config=self.factory.create_config(100, oldest_block=1))
        # getting the receiver
        self._expect_stake_get(public_key='foo', stake=self.factory.create_stake(owner_key='foo',
                                                                                 value=100.0,
                                                                                 block_number=1,
                                                                                 nonce=1))
        self._expect_invalid_transaction()

    def test_send_on_lock_stake(self):
        self._lock(1000)
        self._expect_stake_get(public_key=self._public_key,
                              stake=self.factory.create_stake(owner_key=self._public_key,
                                                             value=1,
                                                             block_number=1,
                                                             nonce=1))
        self._expect_config_get(config=self.factory.create_config(2, oldest_block=1))
        self._expect_stake_set(public_key=self._public_key,
                                   stake=self.factory.create_stake(owner_key=self._public_key,
                                                                   value=1,
                                                                   block_number=1000,
                                                                   nonce=2))
        self._expect_add_event(self._public_key)
        self._expect_ok()

        self._send('foo', 100.0)

        # # getting the sender
        self._expect_stake_get(public_key=self._public_key, stake=self.factory.create_stake(owner_key=self._public_key,
                                                                                            value=100.0,
                                                                                            block_number=1,nonce=1))
        # # getting the config
        self._expect_config_get(config=self.factory.create_config(100, oldest_block=1))
        # # getting the receiver

        self._expect_stake_get(public_key='foo', stake=self.factory.create_stake(owner_key='foo',
                                                                                 value=100.0,
                                                                                 block_number=1,
                                                                                 nonce=1))

        # # setting the sender
        self._expect_stake_set(public_key=self._public_key, stake=self.factory.create_stake(owner_key=self._public_key,
                                                                                            value=0,
                                                                                            block_number=1,
                                                                                            nonce=2))

        self._expect_add_event(self._public_key)

        # # setting the receiver
        self._expect_stake_set(public_key='foo', stake=self.factory.create_stake(owner_key='foo',
                                                                                 value=200.0,
                                                                                 block_number=1,
                                                                                 nonce=2))
        self._expect_add_event('foo')
        #self._expect_invalid_transaction()
        self._expect_ok()



        #case  1 valid transaction
        # a. sender and receiver exists and transaction amount is less than sender stake value, sender and receiver stakes are not locked
        # b. sender exists and transaction amount is less than sender stake value sender is not locked
        # c. special case where sender attempts to send 0 transaction amount (valid transaction but no change in the stake values and also should the receiver be cretaed if it doesnt exist)
        # d. zero amount transactions on the chain and its impact
        # case 2 Invalid transaction
        # a. invalid signer
        # b. transaction amount greater than sender stake amount
        # c.  sender or receiver stakes are locked
        # d. sender block is greater than current block
        # case 3: Other cases
        # a. Transaction amount limit
        # case 4:  Reporting/ alert cases
        # a. when do we want to suspect a particular transaction may be a fraud transaction

    # def test_send_with_bad_signer(self):
    #     self._expect_invalid_transaction()
    #
    # def test_send_without_value(self):
    #     self._expect_invalid_transaction()
    #
    # def test_send_stake_that_dne(self):
    #     """
    #     Tests sending stake from an address that is empty.
    #     This should return an invalid transaction.
    #     """
    #     self._expect_invalid_transaction()
    #
    # def test_send_stake_not_owned(self):
    #     """
    #     Tests sending stake from an address that exists, but does
    #     not match the signing key of this transaction. This should
    #     return an invalid transaction.
    #     """
    #     self._expect_invalid_transaction()
    #
    # # Admissible but perhaps not desired?
    # def test_send_stake_without_name(self):
    #     """
    #     Tests send stake to a name that doesnt exist
    #     """
    #     self._expect_invalid_transaction()
    #
    # def test_lock_stake(self):
    #     """
    #     Tests locking the stake.
    #     """
    #     self._expect_ok()
    #
    # def test_lock_stake_that_dne(self):
    #     """
    #     Tests locking stake that does not exist.
    #     """
    #     self._expect_invalid_transaction()
    #
    # def test_lock_stake_not_owned(self):
    #     """
    #     Tests locking someone else's stake
    #     """
    #     self._expect_invalid_transaction()
    #
    # # Should this be allowed?
    # def test_lock_stake_that_is_already_locked(self):
    #     """
    #     Tests locking stake that is already locked.
    #     """
    #     self._expect_invalid_transaction()
