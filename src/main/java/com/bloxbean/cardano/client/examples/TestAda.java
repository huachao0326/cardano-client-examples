package com.hb.trust.service.impl;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressService;
import com.bloxbean.cardano.client.backend.api.*;
import com.bloxbean.cardano.client.backend.api.helper.FeeCalculationService;
import com.bloxbean.cardano.client.backend.api.helper.TransactionHelperService;
import com.bloxbean.cardano.client.backend.api.helper.UtxoTransactionBuilder;
import com.bloxbean.cardano.client.backend.api.helper.model.TransactionResult;
import com.bloxbean.cardano.client.backend.exception.ApiException;
import com.bloxbean.cardano.client.backend.factory.BackendFactory;
import com.bloxbean.cardano.client.backend.impl.blockfrost.common.Constants;
import com.bloxbean.cardano.client.backend.model.Asset;
import com.bloxbean.cardano.client.backend.model.ProtocolParams;
import com.bloxbean.cardano.client.backend.model.Result;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.KeyGenUtil;
import com.bloxbean.cardano.client.crypto.Keys;
import com.bloxbean.cardano.client.crypto.SecretKey;
import com.bloxbean.cardano.client.crypto.VerificationKey;
import com.bloxbean.cardano.client.metadata.Metadata;
import com.bloxbean.cardano.client.metadata.cbor.CBORMetadata;
import com.bloxbean.cardano.client.metadata.cbor.CBORMetadataList;
import com.bloxbean.cardano.client.metadata.cbor.CBORMetadataMap;
import com.bloxbean.cardano.client.transaction.TransactionSigner;
import com.bloxbean.cardano.client.transaction.model.MintTransaction;
import com.bloxbean.cardano.client.transaction.model.PaymentTransaction;
import com.bloxbean.cardano.client.transaction.model.TransactionDetailsParams;
import com.bloxbean.cardano.client.transaction.spec.*;
import com.bloxbean.cardano.client.transaction.spec.script.ScriptAtLeast;
import com.bloxbean.cardano.client.transaction.spec.script.ScriptPubkey;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.client.util.JsonUtil;
import com.bloxbean.cardano.client.util.PolicyUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Slf4j
public class TestAda extends BaseTest{

    public static void main(String[] args) throws Exception {
        Account sender = new Account(Networks.testnet(), "damp wish scrub sentence vibrant gauge tumble raven game extend winner acid side amused vote edge affair buzz hospital slogan patient drum day vital");
        log.info(HexUtil.encodeHexString(sender.hdKeyPair().getPublicKey().getKeyHash()));
        System.out.println(sender.getBech32PrivateKey());
        String keyCbor = "5820c393da4a70c478b4b7eb06d92aed6e78a2f704a82a7bf24704f58edc3c886c55";
        SecretKey skey = new SecretKey();
        skey.setCborHex(keyCbor);
        VerificationKey vkey = KeyGenUtil.getPublicKeyFromPrivateKey(skey);
        ScriptPubkey scriptPubkey = ScriptPubkey.create(vkey);
        System.out.println(scriptPubkey.getPolicyId());
        System.out.println(scriptPubkey.getKeyHash());
        System.out.println(scriptPubkey.getScriptHash());
        Address address = AddressService.getInstance().getEntAddress(scriptPubkey,Networks.testnet());
        System.out.println(address.getAddress());
        System.out.println("======");

    }

    @Test
    public void getAssets() throws Exception {
        Result<Asset> asset = assetService.getAsset(policyId + assetName);
        System.out.println(JsonUtil.getPrettyJson(asset.getValue()));
    }

    @Test
    public void adaTransfer() throws Exception {
        Account sender = new Account(Networks.testnet(), "modify color old height venture symptom person resist fire clown bike afford bracket talk dice mimic square thank element spend melt local avocado method");
        PaymentTransaction paymentTransaction = PaymentTransaction.builder()
                .sender(sender)
                .receiver("addr_test1qrpwksuzsw89hpenswrnl2tj92k4mmn937pd47r40puy8300pqznkdzlqhznhdvxjhj0lchf4hnnukskdngzm7gtc6wqwt947j")
                .amount(BigInteger.valueOf(10000000))
                .unit("lovelace")//单位
                .build();
        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;
        TransactionDetailsParams detailsParams =
                TransactionDetailsParams.builder()
                        .ttl(ttl)
                        .build();
        BigInteger fee
                = feeCalculationService.calculateFee(paymentTransaction, detailsParams, null);
        paymentTransaction.setFee(fee);

        Result<TransactionResult> result =
                transactionHelperService.transfer(paymentTransaction, detailsParams);

        if (result.isSuccessful())
            System.out.println("Transaction Id: " + result.getValue().getTransactionId());
    }

    @Test
    public void tokenTransfer() throws Exception {
        Account sender = new Account(Networks.testnet(), "modify color old height venture symptom person resist fire clown bike afford bracket talk dice mimic square thank element spend melt local avocado method");
        PaymentTransaction paymentTransaction = PaymentTransaction.builder()
                .sender(sender)
                .receiver("addr_test1qrpwksuzsw89hpenswrnl2tj92k4mmn937pd47r40puy8300pqznkdzlqhznhdvxjhj0lchf4hnnukskdngzm7gtc6wqwt947j")
                .amount(BigInteger.valueOf(3000))
                .unit("394b73a9c71c140a75273749b6dbc66df6590aa53f5aabc2fce2f66754657374436f696e")//单位  policyId + AssetName  (String assetName = HexUtil.encodeHexString("TestCoin".getBytes(StandardCharsets.UTF_8)))
                .build();
        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;
        TransactionDetailsParams detailsParams =
                TransactionDetailsParams.builder()
                        .ttl(ttl)
                        .build();
        BigInteger fee
                = feeCalculationService.calculateFee(paymentTransaction, detailsParams, null);
        paymentTransaction.setFee(fee);

        Result<TransactionResult> result =
                transactionHelperService.transfer(paymentTransaction, detailsParams);

        if (result.isSuccessful())
            System.out.println("Transaction Id: " + result.getValue().getTransactionId());

    }

    @Test
    public void mintToken() throws Exception {
        Account sender = new Account(Networks.testnet(), "modify color old height venture symptom person resist fire clown bike afford bracket talk dice mimic square thank element spend melt local avocado method");
        /**
         * 随机生成policyId
         */
        Keys keys = KeyGenUtil.generateKey();
        VerificationKey vkey = keys.getVkey();
        SecretKey skey = keys.getSkey();

        /**
         * 固定policyId
         */
//        byte[] prvKeyBytes = sender.privateKeyBytes();
//        byte[] pubKeyBytes = sender.publicKeyBytes();
//        SecretKey skey = SecretKey.create(prvKeyBytes);
//        VerificationKey vkey = VerificationKey.create(pubKeyBytes);

        System.out.println(skey.getCborHex());
        ScriptPubkey scriptPubkey = ScriptPubkey.create(vkey);
        String policyId = scriptPubkey.getPolicyId();
        MultiAsset multiAsset = new MultiAsset();
        multiAsset.setPolicyId(policyId);
        com.bloxbean.cardano.client.transaction.spec.Asset asset = new com.bloxbean.cardano.client.transaction.spec.Asset("BEB", BigInteger.valueOf(10000));
        multiAsset.getAssets().add(asset);

        CBORMetadataMap tokenInfoMap
                = new CBORMetadataMap()
                .put("token", "Test Token")
                .put("symbol", "TTOK");

        CBORMetadataList tagList
                = new CBORMetadataList()
                .add("tag1")
                .add("tag2");

        Metadata metadata = new CBORMetadata()
                .put(new BigInteger("770001"), tokenInfoMap)
                .put(new BigInteger("770002"), tagList);


        MintTransaction mintTransaction =
                MintTransaction.builder()
                        .sender(sender)
                        .mintAssets(Arrays.asList(multiAsset))
                        .policyScript(scriptPubkey)
                        .policyKeys(Arrays.asList(skey))
                        .build();

        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;
        TransactionDetailsParams detailsParams =
                TransactionDetailsParams.builder()
                        .ttl(ttl)
                        .build();
        BigInteger fee
                = feeCalculationService.calculateFee(mintTransaction, detailsParams, metadata);
        mintTransaction.setFee(fee);

        Result<TransactionResult> result
                = transactionHelperService.mintToken(mintTransaction, detailsParams, metadata);
        if (result.isSuccessful())
            System.out.println("Transaction Id: " + result.getValue().getTransactionId());
        else
            System.out.println("Transaction failed: " + result);
    }

    @Test
    public void addToken() throws Exception{
        Account sender = new Account(Networks.testnet(), "modify color old height venture symptom person resist fire clown bike afford bracket talk dice mimic square thank element spend melt local avocado method");
        /**
         * 记录cborHex，增发使用
         * skey.getCborHex()
         */
        SecretKey skey = new SecretKey();
        skey.setCborHex("58207096361615ee87d13b737c4aee8bea9caa8c0c01abd5326354255097f9549455");
        VerificationKey vkey = KeyGenUtil.getPublicKeyFromPrivateKey(skey);
        ScriptPubkey scriptPubkey = ScriptPubkey.create(vkey);
        String policyId = scriptPubkey.getPolicyId();
        MultiAsset multiAsset = new MultiAsset();
        multiAsset.setPolicyId(policyId);
        com.bloxbean.cardano.client.transaction.spec.Asset asset = new com.bloxbean.cardano.client.transaction.spec.Asset("BDB", BigInteger.valueOf(50000));
        multiAsset.getAssets().add(asset);

        CBORMetadataMap tokenInfoMap
                = new CBORMetadataMap()
                .put("token", "Test Token")
                .put("symbol", "TTOK");

        CBORMetadataList tagList
                = new CBORMetadataList()
                .add("tag1")
                .add("tag2");

        Metadata metadata = new CBORMetadata()
                .put(new BigInteger("770001"), tokenInfoMap)
                .put(new BigInteger("770002"), tagList);


        MintTransaction mintTransaction =
                MintTransaction.builder()
                        .sender(sender)
                        .mintAssets(Arrays.asList(multiAsset))
                        .policyScript(scriptPubkey)
                        .policyKeys(Arrays.asList(skey))
                        .build();

        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;
        TransactionDetailsParams detailsParams =
                TransactionDetailsParams.builder()
                        .ttl(ttl)
                        .build();


        BigInteger fee
                = feeCalculationService.calculateFee(mintTransaction, detailsParams, metadata);
        mintTransaction.setFee(fee);

        Result<TransactionResult> result
                = transactionHelperService.mintToken(mintTransaction, detailsParams, metadata);
        if (result.isSuccessful())
            System.out.println("Transaction Id: " + result.getValue().getTransactionId());
        else
            System.out.println("Transaction failed: " + result);
    }

    @Test
    public void adaMultiSign() throws Exception {
        ScriptPubkey key1 = new ScriptPubkey();
        key1.setKeyHash("d80a0ccc087c8aacaba7ffb6a99ea2a315448ab3aba7b036320d8b57");

        ScriptPubkey key2 = new ScriptPubkey();
        key2.setKeyHash("af2c93defdea53a156ae6f3f55bd4653a5c229ea33d94cb75d927c9f");

        ScriptPubkey key3 = new ScriptPubkey();
        key3.setKeyHash("c4b2ff497c18528b0c6ad337a3cae6b4e5049a66e3a1598daed4a256");

        ScriptAtLeast scriptAtLeast = new ScriptAtLeast(2);
        scriptAtLeast.addScript(key1)
                .addScript(key2)
                .addScript(key3);
        String multisigScriptAddr = AddressService.getInstance().getEntAddress(scriptAtLeast, Networks.testnet()).toBech32();

        log.info(multisigScriptAddr);
        String receiverAddress = "addr_test1qrpwksuzsw89hpenswrnl2tj92k4mmn937pd47r40puy8300pqznkdzlqhznhdvxjhj0lchf4hnnukskdngzm7gtc6wqwt947j";
        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;

        TransactionOutput change = TransactionOutput
                .builder()
                .address("addr_test1wptcw0x3sxuuaj7ztc693y8rh3v2kheawy2492p7cdhd8asl8ea2l")
                .value(Value.builder().coin(BigInteger.valueOf(73600000))
                        .build())
                .build();
        TransactionOutput output = TransactionOutput.builder()
                .address(receiverAddress)
                .value(Value.builder()
                        .coin(BigInteger.valueOf(5000000))
                        .build())
                .build();
        List<TransactionOutput> outputs = Arrays.asList(output, change);

        TransactionBody body = TransactionBody.builder()
                .networkId(NetworkId.TESTNET)
                .inputs(Collections.singletonList(TransactionInput.builder()
                        .transactionId("879d73c9f3131a9dda73e5a7863592e9484857c38ca958fb8591370c0346ff42")
                        .index(1)
                        .build()))
                .outputs(outputs)
                .fee(BigInteger.valueOf(365606))
                .ttl(ttl)
                .build();

        Transaction tx = Transaction.builder()
                .body(body)
                .build();

        TransactionWitnessSet transactionWitnessSet = new TransactionWitnessSet();
        transactionWitnessSet.setNativeScripts(Arrays.asList(scriptAtLeast));
        tx.setWitnessSet(transactionWitnessSet);
        Account signer1 = new Account(Networks.testnet(), "wing boring rural coast print critic obscure grant shop course charge donate code diamond jelly tunnel solar ticket click cinnamon moral echo ice pencil");
        Transaction signTxn = signer1.sign(tx);

        String finalSignedTxn = signTxn.serializeToHex();

        Account signer2 = new Account(Networks.testnet(), "cricket deputy typical plug arrow nice muscle film first kidney just expire grit pull envelope amused eagle monitor sample eye spike broom picture adapt");
        Transaction txn2 = Transaction.deserialize(HexUtil.decodeHexString(finalSignedTxn));
        Transaction signTxn2 = signer2.sign(txn2);

        Result<String> result = transactionService.submitTransaction(signTxn2.serialize());
        log.info("=====");
    }

    @Test
    public void tokenMultiSign() throws Exception {
        ScriptPubkey key1 = new ScriptPubkey();
        key1.setKeyHash("d80a0ccc087c8aacaba7ffb6a99ea2a315448ab3aba7b036320d8b57");

        ScriptPubkey key2 = new ScriptPubkey();
        key2.setKeyHash("af2c93defdea53a156ae6f3f55bd4653a5c229ea33d94cb75d927c9f");

        ScriptPubkey key3 = new ScriptPubkey();
        key3.setKeyHash("c4b2ff497c18528b0c6ad337a3cae6b4e5049a66e3a1598daed4a256");

        ScriptAtLeast scriptAtLeast = new ScriptAtLeast(2);
        scriptAtLeast.addScript(key1)
                .addScript(key2)
                .addScript(key3);
        String multisigScriptAddr = AddressService.getInstance().getEntAddress(scriptAtLeast, Networks.testnet()).toBech32();

        log.info(multisigScriptAddr);
        String receiverAddress = "addr_test1qrpwksuzsw89hpenswrnl2tj92k4mmn937pd47r40puy8300pqznkdzlqhznhdvxjhj0lchf4hnnukskdngzm7gtc6wqwt947j";
        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;

        PaymentTransaction paymentTransaction = PaymentTransaction.builder()
                .sender(new ReadOnlyAccount(multisigScriptAddr))
                .receiver(receiverAddress)
                .amount(BigInteger.valueOf(200))
                .unit("394b73a9c71c140a75273749b6dbc66df6590aa53f5aabc2fce2f66754657374436f696e")//单位  policyId + AssetName  (String assetName = HexUtil.encodeHexString("TestCoin".getBytes(StandardCharsets.UTF_8)))
                .build();
        paymentTransaction.setFee(BigInteger.valueOf(300000));
        TransactionDetailsParams detailsParams =
                TransactionDetailsParams.builder()
                        .ttl(ttl)
                        .build();
        ProtocolParams protocolParams = epochService.getProtocolParameters().getValue();
        Transaction tx = utxoTransactionBuilder.buildTransaction(Arrays.asList(paymentTransaction), detailsParams, null, protocolParams);

        TransactionWitnessSet transactionWitnessSet = new TransactionWitnessSet();
        transactionWitnessSet.setNativeScripts(Arrays.asList(scriptAtLeast));
        tx.setWitnessSet(transactionWitnessSet);
        Account signer1 = new Account(Networks.testnet(), "wing boring rural coast print critic obscure grant shop course charge donate code diamond jelly tunnel solar ticket click cinnamon moral echo ice pencil");
        Transaction signTxn = signer1.sign(tx);


        String finalSignedTxn = signTxn.serializeToHex();

        Account signer2 = new Account(Networks.testnet(), "cricket deputy typical plug arrow nice muscle film first kidney just expire grit pull envelope amused eagle monitor sample eye spike broom picture adapt");
        Transaction txn2 = Transaction.deserialize(HexUtil.decodeHexString(finalSignedTxn));
        Transaction signTxn2 = signer2.sign(txn2);
        String finalSignedTxn2 = signTxn2.serializeToHex();
        log.info(finalSignedTxn2);

        Result<String> result = transactionService.submitTransaction(signTxn2.serialize());
        log.info(result.getValue());
    }

    @Test
    public void mintMultiSign() throws Exception {
        ScriptPubkey key1 = new ScriptPubkey();
        key1.setKeyHash("d80a0ccc087c8aacaba7ffb6a99ea2a315448ab3aba7b036320d8b57");

        ScriptPubkey key2 = new ScriptPubkey();
        key2.setKeyHash("af2c93defdea53a156ae6f3f55bd4653a5c229ea33d94cb75d927c9f");

        ScriptPubkey key3 = new ScriptPubkey();
        key3.setKeyHash("c4b2ff497c18528b0c6ad337a3cae6b4e5049a66e3a1598daed4a256");

        ScriptAtLeast scriptAtLeast = new ScriptAtLeast(2);

        scriptAtLeast.addScript(key1)
                .addScript(key2)
                .addScript(key3);
        String multisigScriptAddr = AddressService.getInstance().getEntAddress(scriptAtLeast, Networks.testnet()).toBech32();//addr_test1wptcw0x3sxuuaj7ztc693y8rh3v2kheawy2492p7cdhd8asl8ea2l
        log.info(multisigScriptAddr);

//        Keys keys = KeyGenUtil.generateKey();
//        VerificationKey vkey = keys.getVkey();
//        SecretKey skey = keys.getSkey();
//        System.out.println(skey.getCborHex());
//        ScriptPubkey scriptPubkey = ScriptPubkey.create(vkey);
//        String policyId = scriptPubkey.getPolicyId();
        String keyCbor = "582060472be03fbccbac7755169c2c9fab9a35e1a76a9c8a949ab43bd257c134d898";
        SecretKey skey = new SecretKey();
        skey.setCborHex(keyCbor);
        VerificationKey vkey = KeyGenUtil.getPublicKeyFromPrivateKey(skey);
        ScriptPubkey scriptPubkey = ScriptPubkey.create(vkey);
        String policyId = scriptPubkey.getPolicyId();
        MultiAsset multiAsset = new MultiAsset();
        multiAsset.setPolicyId(policyId);
        com.bloxbean.cardano.client.transaction.spec.Asset asset = new com.bloxbean.cardano.client.transaction.spec.Asset("BDDB", BigInteger.valueOf(30000));
        multiAsset.getAssets().add(asset);

        CBORMetadata metadata = new CBORMetadata();
        metadata.put(BigInteger.valueOf(10000001), "mint Test");

        MintTransaction mintTransaction =
                MintTransaction.builder()
                        .sender(new ReadOnlyAccount(multisigScriptAddr))
                        .receiver("addr_test1qrpwksuzsw89hpenswrnl2tj92k4mmn937pd47r40puy8300pqznkdzlqhznhdvxjhj0lchf4hnnukskdngzm7gtc6wqwt947j")
                        .mintAssets(Arrays.asList(multiAsset))
                        .policyScript(scriptPubkey)
                        .policyKeys(Arrays.asList(skey))
                        .build();
        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;
        TransactionDetailsParams detailsParams =
                TransactionDetailsParams.builder()
                        .ttl(ttl)
                        .build();
        mintTransaction.setFee(BigInteger.valueOf(300000));

        Result<ProtocolParams> protocolParamsResult = epochService.getProtocolParameters();
        if (!protocolParamsResult.isSuccessful())
            throw new ApiException("Unable to fetch protocol parameters to build transaction");

        ProtocolParams protocolParams = protocolParamsResult.getValue();
        Transaction transaction = utxoTransactionBuilder.buildMintTokenTransaction(mintTransaction, detailsParams, metadata, protocolParams);

//        transaction.setValid(true);
        TransactionWitnessSet transactionWitnessSet = new TransactionWitnessSet();
        transactionWitnessSet.getNativeScripts().add(mintTransaction.getPolicy().getPolicyScript());
        transactionWitnessSet.getNativeScripts().addAll(Arrays.asList(scriptAtLeast));
        transaction.setWitnessSet(transactionWitnessSet);

        Account signer1 = new Account(Networks.testnet(), "wing boring rural coast print critic obscure grant shop course charge donate code diamond jelly tunnel solar ticket click cinnamon moral echo ice pencil");
        Transaction signTxn = signer1.sign(transaction);
        for (SecretKey key : mintTransaction.getPolicy().getPolicyKeys()) {
            signTxn = TransactionSigner.INSTANCE.sign(signTxn, key);
        }
        String finalSignedTxn = signTxn.serializeToHex();
        log.info(finalSignedTxn);

        Account signer2 = new Account(Networks.testnet(), "cricket deputy typical plug arrow nice muscle film first kidney just expire grit pull envelope amused eagle monitor sample eye spike broom picture adapt");
        Transaction txn2 = Transaction.deserialize(HexUtil.decodeHexString(finalSignedTxn));
        Transaction signTxn2 = signer2.sign(txn2);
        String finalSignedTxn2 = signTxn2.serializeToHex();
        log.info(finalSignedTxn2);


        Result<String> result = transactionService.submitTransaction(signTxn2.serialize());
        log.info(result.getValue());
    }

    @Test
    void mintTokenWithScriptAtLeast() throws Exception {
        Policy policy = PolicyUtil.createMultiSigScriptAtLeastPolicy("scriptAtLeast", 3, 2);

        String senderMnemonic = "damp wish scrub sentence vibrant gauge tumble raven game extend winner acid side amused vote edge affair buzz hospital slogan patient drum day vital";
        Account sender = new Account(Networks.testnet(), senderMnemonic);
        String receiver = "addr_test1qqwpl7h3g84mhr36wpetk904p7fchx2vst0z696lxk8ujsjyruqwmlsm344gfux3nsj6njyzj3ppvrqtt36cp9xyydzqzumz82";
        long ttl = blockService.getLastestBlock().getValue().getSlot() + 20000;
        MultiAsset multiAsset = new MultiAsset();
        multiAsset.setPolicyId(policy.getPolicyId());
        com.bloxbean.cardano.client.transaction.spec.Asset asset = new com.bloxbean.cardano.client.transaction.spec.Asset("selftoken1", BigInteger.valueOf(250000));
        multiAsset.getAssets().add(asset);

        MintTransaction paymentTransaction =
                MintTransaction.builder()
                        .sender(sender)
                        .receiver(receiver)
                        .mintAssets(Arrays.asList(multiAsset))
                        .policy(policy)
                        .build();

        paymentTransaction.setFee(BigInteger.valueOf(300000));

        Result<TransactionResult> result = transactionHelperService.mintToken(paymentTransaction,
                TransactionDetailsParams.builder().ttl(ttl).build());

        System.out.println("Request: \n" + JsonUtil.getPrettyJson(paymentTransaction));
        System.out.println(result);
        if (result.isSuccessful())
            System.out.println("Transaction Id: " + result.getValue());
        else
            System.out.println("Transaction failed: " + result);

    }

    static class ReadOnlyAccount extends Account {
        private String address;

        public ReadOnlyAccount(String address) {
            this.address = address;
        }

        @Override
        public String baseAddress() {
            return address;
        }
    }

}
