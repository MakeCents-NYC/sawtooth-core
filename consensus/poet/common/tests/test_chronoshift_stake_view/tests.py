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
import unittest

from sawtooth_poet_common.protobuf.stake_pb2 import StakeList
from sawtooth_poet_common.protobuf.stake_pb2 import Stake
from sawtooth_poet_common.chronoshift_stake_view.chronoshift_stake_view \
    import ChronoShiftStakeView

from test_chronoshift_stake_view.mocks import MockStateView
from test_chronoshift_stake_view.utils import to_address


class TestChronoShiftStakeView(unittest.TestCase):

    def test_get_stake_info(self):
        data = StakeList()
        data.stakeMap.get_or_create('my_key')
        data.stakeMap['my_key'].balance = 50.0
        data.stakeMap['my_key'].ownerPubKey = 'my_key'
        data.stakeMap['my_key'].nonce = 1
        data.stakeMap['my_key'].blockNumber = 100
        data.SerializeToString()

        # Stored like a state
        state_view = MockStateView({
            to_address('my_key'): data
        })

        # create a state view
        chronoshift_stake_view = ChronoShiftStakeView(state_view)

        info = chronoshift_stake_view.get_stake('my_key')
        ret_data = StakeList()
        ret_data.parseFromString(info[0])
        self.assertEqual(ret_data.stakeMap['my_key'].ownerPubKey, 'my_key')
        self.assertEqual(ret_data.stakeMap['my_key'].balance, 50.0)
        self.assertEqual(ret_data.stakeMap['my_key'].nonce, 1)
        self.assertEqual(ret_data.stakeMap['my_key'].blockNumber, 100)

    def test_get_stake_at_state_that_does_not_exist(self):
        state_view = MockStateView({})
        chronoshift_stake_view = ChronoShiftStakeView(state_view)

        with self.assertRaises(KeyError):
            chronoshift_stake_view.get_stake('my_id')

    def test_stake_cache(self):
        pass