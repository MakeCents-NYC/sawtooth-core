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


class TestStake(TransactionProcessorTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.factory = StakeMessageFactory()

    # expect getting a stake address
    def _expect_stake_get(self, key, allowed=True):
        pass

    def _expect_stake_set(self, total_supply, public_key):
        recieved = self.validator.expect(
            self.factory.create_mint_stake_request(total_supply, public_key))

        self.validator.respond(
            self.factory.create_mint_stake_response(public_key),
            recieved)

    # creates the initial supply
    def _mint(self):
        self.validator.send(self.factory.create_mint_stake_transaction(100.0, self._public_key))

    # send a role to be created in state to validator
    def _send(self, name, value):
        pass

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

    def test_mint_total_supply(self):
        """
        Tests initializing the total supply, it checks the minting
        key address to see if the signer of the transaction is correct.
        """
        self._mint()
        self._expect_setting_get(MINT_KEY_ADDRESS)
        self._expect_stake_set(100.0, self._public_key)
        self._expect_ok()

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
