#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, find_output

import json
import os

MAX_BIP125_RBF_SEQUENCE = 0xfffffffd

class RegtestSignatureTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 1

    def run_test(self):
        bitcoind = self.nodes[0]

        bitcoin_lib_script_sig = "0047304402201aaadac2eade5e3aa0d77ad788f7e98b868016dfc063f902bf8633fa4fa1696102205b419ff65d661b851ef406c89b7cdcd808617c3518f1ce01723c640d3a34182801483045022100da147e6710275c7b519ce3276fb1c03096ff8a2ab39006cec210817d334451ad02203639b969c78aa06d1b3e3224c47a1316e76a34f35f04da2ca1898a39d4eb3c4201475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae"

        #index of the unspent output funding the p2sh
        p2sh_out_index = 0
        p2sh_value = 10
        redeem_script_raw = "5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae"

        #load regtest blocks file
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/regtest_blocks.json'), encoding='utf-8') as f:
            raw_blocks = json.load(f)
            
        print("Submitting blocks")
        for block in raw_blocks:
            bitcoind.submitblock(block)

        print("Done.")
        print("Syncing...")
        self.sync_all()
        print("Done syncing.")

        #exactly 572 blocks were generated in regtest
        info = bitcoind.getblockchaininfo()
        assert info['blocks'] == 572

        # funding tx id
        funding_txid = 'cd23b89604584d7189eafbe3fcf340ae1ee028a3904edd5d0a471038615311b6'
        funding_raw = bitcoind.getrawtransaction(funding_txid, True)

        #script pubkey embedded in the output: OP_HASH160 0fb9463421696b82c833af241c78c17ddbde4934 OP_EQUAL
        scriptPubKey = funding_raw["vout"][p2sh_out_index]["scriptPubKey"]["hex"]

        #infos used when we sign the inputs spending the p2sh output
        prev_txs = [{"txid": funding_txid, "vout": p2sh_out_index, "scriptPubKey": scriptPubKey, "redeemScript": redeem_script_raw, "amount": p2sh_value}]

        #create a transaction that spends the p2sh output - sends the fund to hardcoded 2Mx1vp4fnSeHEbWopkGvgjpDittT3Vt4uvQ
        raw_tx = bitcoind.createrawtransaction([{"txid": funding_txid, "vout": p2sh_out_index}], [{"2Mx1vp4fnSeHEbWopkGvgjpDittT3Vt4uvQ": p2sh_value}])

        #print("RAW_TX:"+str(raw_tx))

        #now sign it! 
        signed_raw_tx = bitcoind.signrawtransactionwithkey(raw_tx, ['cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr'], prev_txs)
        
        #one signature is not enough
        assert signed_raw_tx["complete"] == False
        
        #add the second missing signature 
        signed_raw_tx = bitcoind.signrawtransactionwithkey(signed_raw_tx["hex"], ['cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au'], prev_txs)

        #with two signatures the 2-of-2 multisig is complete
        assert signed_raw_tx["complete"] == True
        
        #extract the produced script_sig and compare it with the expected one (from bitcoin-lib)
        decoded = bitcoind.decoderawtransaction(signed_raw_tx["hex"])
        script_sig = decoded["vin"][0]["scriptSig"]

        print("\nSCRIPT_SIG: "+str(script_sig["asm"]))

        assert script_sig["hex"] == bitcoin_lib_script_sig       

if __name__ == '__main__':
    RegtestSignatureTest().main()
