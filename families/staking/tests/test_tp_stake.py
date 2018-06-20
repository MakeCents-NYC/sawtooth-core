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

from sawtooth_identity_test.stake_message_factory \
    import StakeMessageFactory

from sawtooth_processor_test.transaction_processor_test_case \
    import TransactionProcessorTestCase



MINT_KEY_ADDRESS = '000000a87cb5eafdcca6a8f4caf4ff95731a23f91e6901b1da081ee3b0c44298fc1c14'

FAMILY_NAME = 'block_info'
FAMILY_VERSION = '1.0'
NAMESPACE = '00b10c'
BLOCK_INFO_NAMESPACE = NAMESPACE + '00'
CONFIG_ADDRESS = NAMESPACE + '01' + '0' * 62
DEFAULT_SYNC_TOLERANCE = 60 * 5
DEFAULT_TARGET_COUNT = 256


class TestStake(TransactionProcessorTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.factory = StakeMessageFactory()

    # expect getting a stake address
    def _expect_stake_get(self, public_key=None, stake=None):
        """

        :param public_key: The key used to generate the stake address to fetch
        :param stake_alloc: A dictionary with the expected return value
        :return:
        """
        recieved = self.validator.expect(
            self.factory.create_get_stake_request(public_key))

        self.validator.respond(
            self.factory.create_get_stake_response(public_key, stake),
            recieved)

    def _expect_stake_set(self, stake=None):
        recieved = self.validator.expect(
            self.factory.create_set_stake_request(self._public_key, stake=stake))

        self.validator.respond(
            self.factory.create_mint_stake_response(self._public_key),
            recieved)

    def _expect_mint_stake_set(self, total_supply, public_key):
        recieved = self.validator.expect(
            self.factory.create_mint_stake_request(total_supply, public_key))

        self.validator.respond(
            self.factory.create_mint_stake_response(public_key),
            recieved)

    # creates the initial supply
    def _mint(self, total_supply, public_key):
        self.validator.send(self.factory.create_mint_stake_transaction(total_supply, public_key))

    # send a role to be created in state to validator
    def _send(self, name, value):
        pass

    # send a lock command to validator
    def _lock(self, block_number):
        self.validator.send(self.factory.create_lock_stake_transaction(block_number))

    def _expect_setting_get(self, key, allowed=True):
        recieved = self.validator.expect(
            self.factory.create_get_setting_request(key))

        self.validator.respond(
            self.factory.create_get_setting_response(key, allowed),
            recieved)

    def _expect_config_get(self, config=None):
        received = self.validator.expect(
            self.factory.create_get_block_config_request())

        response = {} if config is None \
            else {CONFIG_ADDRESS: config.SerializeToString()}
        self.validator.respond(
            self.factory.create_get_block_config_response(response), received)

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

    def test_mint_total_supply(self):
        """
        Tests initializing the total supply, it checks the minting
        key address to see if the signer of the transaction is correct.
        """
        self._mint(100.0, self._public_key)
        self._expect_setting_get(MINT_KEY_ADDRESS)
        self._expect_mint_stake_set(100.0, self._public_key)
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

    def test_lock_transaction(self):
        self._lock(1000)
        self._expect_stake_get(self._public_key, stake=self.factory.create_stake(owner_key=self._public_key,
                                                                                 value=1,
                                                                                 block_number=1,
                                                                                 ))
        self._expect_config_get(config=self.factory.create_config(2, oldest_block=1))
        # stake = Stake(nonce=1, value=1, blockNumber=1, ownerPubKey=self._public_key)
        # stake_list = self.factory.build_stake_list(stake)
        # self._expect_stake_get(self._public_key, **{self._public_key: stake_list})
        self._expect_stake_set(stake=self.factory.create_stake(owner_key=self._public_key,
                                                               value=1,
                                                               block_number=2,
                                                              ))
        self._expect_ok()

        # test_send
        # self._send(50, "asdf")
        # st_s = {"ownerPubKey": self._public_key, "value": 50}
        # st_r = {"ownerPubKey": 'asdf', "value": 50}
        # self._expect_stake_get(self._public_key, **st_)
        # self._expect_stake_get(self._public_key, **st)
        # self._expect_stake_set(self._public_key, **st)
        # self._expect_stake_set(self._public_key, **st)
        # self._expect_add_event()
        # self._expect_ok()
    # def test_send_stake(self):
    #     """
    #     Tests sending some stake
    #     """
    #     self._expect_ok()
    #
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
