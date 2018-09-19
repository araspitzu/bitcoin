#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, find_output

import json
import os

MAX_BIP125_RBF_SEQUENCE = 0xfffffffd

class PSBTSignatureTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 2

    def run_test(self):

        #expected values
        p2sh_value = 10 
        bitcoin_lib_script_sig = '00473044022021648b4e1a1a2e0f57c1a376cda933f45b4c4a39e19b5d98313d22223e2c8d5f0220508bc46b5b0b967d67957cede9e418d68b8a835fdf5ca10cf622ab431eed652201483045022100c02abac802292e3c68ccbd08d4f12ac2f2a9f23337aa7b2d584698e5952817f4022054f6dbb01119be29b7afec1689d89bc88bd349e4a65e9f835141694ed98f823201475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae'
        expected_p2sh_address = '2MtgN5EvHUm2kNVvqKgqsZ9v2fGH3jCpXVF'
        pubkey0 = '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f'
        pubkey1 = '02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7'

        node0, node1 = self.nodes

        #let the nodes find some blocks to have a positive balance
        node0.generate(6)
        self.sync_all()

        #create a 2-of-2 multisig redeem script from node 1 (legacy p2sh) - with the given pubkeys
        p2sh = node1.addmultisigaddress(2, [pubkey0, pubkey1], "", "legacy")
        assert p2sh["address"] == expected_p2sh_address

        #fund the multisig address - use fundrawtransaction?
        txid = node0.sendtoaddress(p2sh["address"], p2sh_value)
        funding_raw = node0.getrawtransaction(txid, True)
        
        #find the p2sh output, the change output index can be forced if we use fundrawtransaction
        p2sh_out_index = [v["n"] for v in funding_raw["vout"] if expected_p2sh_address in v["scriptPubKey"].get("addresses",[])]
        p2sh_out_index = p2sh_out_index[0]
       
        #script pubkey embedded in the output: OP_HASH160 0fb9463421696b82c833af241c78c17ddbde4934 OP_EQUAL
        scriptPubKey = funding_raw["vout"][p2sh_out_index]["scriptPubKey"]["hex"]
        assert scriptPubKey == "a9140fb9463421696b82c833af241c78c17ddbde493487" 

        node0.generate(1)
        self.sync_all()

        #infos used when we sign the inputs spending the p2sh output
        prev_txs = [{"txid": txid, "vout": p2sh_out_index, "scriptPubKey": scriptPubKey, "redeemScript": p2sh["redeemScript"], "amount": p2sh_value}]

        #create a transaction that spends the p2sh output - sends the fund to hardcoded 2Mx1vp4fnSeHEbWopkGvgjpDittT3Vt4uvQ
        raw_tx = node1.createrawtransaction([{"txid": txid, "vout": p2sh_out_index}], [{"2Mx1vp4fnSeHEbWopkGvgjpDittT3Vt4uvQ": p2sh_value}])

        #now sign it! 
        signed_raw_tx = node1.signrawtransactionwithkey(raw_tx, ['cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr'], prev_txs)
        
        #one signature is not enough
        assert signed_raw_tx["complete"] == False
        
        #add the second missing signature 
        signed_raw_tx = node1.signrawtransactionwithkey(signed_raw_tx["hex"], ['cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au'], prev_txs)

        #with two signatures the 2-of-2 multisig is complete
        assert signed_raw_tx["complete"] == True
        
        #extract the produced script_sig and compare it with the expected one (from bitcoin-lib)
        decoded = node1.decoderawtransaction(signed_raw_tx["hex"])
        script_sig = decoded["vin"][0]["scriptSig"]

        print("\nSCRIPT_SIG: "+str(script_sig["asm"]))

        assert script_sig["hex"] == bitcoin_lib_script_sig

        '''
        #PSBT test
        raw_psbt = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAQMEAQAAAAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAAQMEAQAAAAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
        expected_psbt = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210cwRAIgYxqYn+c4qSrQGYYCMxLBkhT+KAKznly8GsNniAbGksMCIDnbbDh70mdxbf2z1NjaULjoXSEzJrp8faqkwM5B65IjAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgICOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="

        self.nodes[0].createwallet("wallet{}".format(0))
        wrpc = self.nodes[0].get_wallet_rpc("wallet{}".format(0))

        #decoded = wrpc.decodepsbt(raw_psbt)
        #print(decoded)

        wrpc.importprivkey('cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au')
        wrpc.importprivkey('cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE')

        signed_tx = wrpc.walletprocesspsbt(raw_psbt)['psbt']
        assert_equal(signed_tx, expected_psbt)
        '''

'''
rawPsbt:
{
   "tx":{
      "txid":"82efd652d7ab1197f01a5f4d9a30cb4c68bb79ab6fec58dfa1bf112291d1617b",
      "hash":"82efd652d7ab1197f01a5f4d9a30cb4c68bb79ab6fec58dfa1bf112291d1617b",
      "version":2,
      "size":154,
      "vsize":154,
      "weight":616,
      "locktime":0,
      "vin":[
         {
            "txid":"75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858",
            "vout":0,
            "scriptSig":{
               "asm":"",
               "hex":""
            },
            "sequence":4294967295
         },
         {
            "txid":"1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83",
            "vout":1,
            "scriptSig":{
               "asm":"",
               "hex":""
            },
            "sequence":4294967295
         }
      ],
      "vout":[
         {
            "value":1.49990000,
            "n":0,
            "scriptPubKey":{
               "asm":"0 d85c2b71d0060b09c9886aeb815e50991dda124d",
               "hex":"0014d85c2b71d0060b09c9886aeb815e50991dda124d",
               "reqSigs":1,
               "type":"witness_v0_keyhash",
               "addresses":[
                  "bcrt1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdqpxskv"
               ]
            }
         },
         {
            "value":1.00000000,
            "n":1,
            "scriptPubKey":{
               "asm":"0 00aea9a2e5f0f876a588df5546e8742d1d87008f",
               "hex":"001400aea9a2e5f0f876a588df5546e8742d1d87008f",
               "reqSigs":1,
               "type":"witness_v0_keyhash",
               "addresses":[
                  "bcrt1qqzh2ngh97ru8dfvgma25d6r595wcwqy0cee4cc"
               ]
            }
         }
      ]
   },
   "unknown":{

   },
   "inputs":[
      {
         "non_witness_utxo":{
            "txid":"75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858",
            "hash":"75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858",
            "version":2,
            "size":187,
            "vsize":187,
            "weight":748,
            "locktime":101,
            "vin":[
               {
                  "txid":"8b6f65ab71eeab8b2918acc2ea06b79de08b84680b40ae845fd28b013139d7aa",
                  "vout":0,
                  "scriptSig":{
                     "asm":"3044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba[ALL]",
                     "hex":"473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01"
                  },
                  "sequence":4294967294
               }
            ],
            "vout":[
               {
                  "value":0.50000000,
                  "n":0,
                  "scriptPubKey":{
                     "asm":"OP_HASH160 0fb9463421696b82c833af241c78c17ddbde4934 OP_EQUAL",
                     "hex":"a9140fb9463421696b82c833af241c78c17ddbde493487",
                     "reqSigs":1,
                     "type":"scripthash",
                     "addresses":[
                        "2MtgN5EvHUm2kNVvqKgqsZ9v2fGH3jCpXVF"
                     ]
                  }
               },
               {
                  "value":49.49996240,
                  "n":1,
                  "scriptPubKey":{
                     "asm":"OP_HASH160 29ca74f8a08f81999428185c97b5d852e4063f61 OP_EQUAL",
                     "hex":"a91429ca74f8a08f81999428185c97b5d852e4063f6187",
                     "reqSigs":1,
                     "type":"scripthash",
                     "addresses":[
                        "2Mw4CE6tUQ7Ak9Zf9TKujgzbVjDZqgRbUVP"
                     ]
                  }
               }
            ]
         },
         "sighash":"ALL",
         "redeem_script":{
            "asm":"2 029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f 02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7 2 OP_CHECKMULTISIG",
            "hex":"5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae",
            "type":"multisig"
         },
         "bip32_derivs":[
            {
               "pubkey":"029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f",
               "master_fingerprint":"d90c6a4f",
               "path":"m/0'/0'/0'"
            },
            {
               "pubkey":"02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7",
               "master_fingerprint":"d90c6a4f",
               "path":"m/0'/0'/1'"
            }
         ]
      },
      {
         "witness_utxo":{
            "amount":2.00000000,
            "scriptPubKey":{
               "asm":"OP_HASH160 b7f5faf40e3d40a5a459b1db3535f2b72fa921e8 OP_EQUAL",
               "hex":"a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887",
               "type":"scripthash",
               "address":"2NA1vKQ5z7iMDBBjkCSfZyU84uQV8PJJPtg"
            }
         },
         "sighash":"ALL",
         "redeem_script":{
            "asm":"0 8c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903",
            "hex":"00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903",
            "type":"witness_v0_scripthash"
         },
         "witness_script":{
            "asm":"2 03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc 023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73 2 OP_CHECKMULTISIG",
            "hex":"522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae",
            "type":"multisig"
         },
         "bip32_derivs":[
            {
               "pubkey":"023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73",
               "master_fingerprint":"d90c6a4f",
               "path":"m/0'/0'/3'"
            },
            {
               "pubkey":"03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc",
               "master_fingerprint":"d90c6a4f",
               "path":"m/0'/0'/2'"
            }
         ]
      }
   ],
   "outputs":[
      {
         "bip32_derivs":[
            {
               "pubkey":"03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771",
               "master_fingerprint":"d90c6a4f",
               "path":"m/0'/0'/4'"
            }
         ]
      },
      {
         "bip32_derivs":[
            {
               "pubkey":"027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096",
               "master_fingerprint":"d90c6a4f",
               "path":"m/0'/0'/5'"
            }
         ]
      }
   ],
   "fee":0.00010000
}
'''
if __name__ == '__main__':
    PSBTSignatureTest().main()
