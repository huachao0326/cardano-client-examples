package com.bloxbean.cardano.client.examples;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.helper.model.TransactionResult;
import com.bloxbean.cardano.client.backend.exception.ApiException;
import com.bloxbean.cardano.client.backend.model.Result;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.exception.AddressExcepion;
import com.bloxbean.cardano.client.exception.CborSerializationException;
import com.bloxbean.cardano.client.transaction.model.PaymentTransaction;
import com.bloxbean.cardano.client.transaction.model.TransactionDetailsParams;

import java.math.BigInteger;

public class TransferTokenTest extends BaseTest {

    public void transfer() throws ApiException, AddressExcepion, CborSerializationException {

        String senderMnemonic = "kit color frog trick speak employ suit sort bomb goddess jewel primary spoil fade person useless measure manage warfare reduce few scrub beyond era";
        Account sender = new Account(Networks.testnet(), senderMnemonic);

        String receiver = "addr_test1qqwpl7h3g84mhr36wpetk904p7fchx2vst0z696lxk8ujsjyruqwmlsm344gfux3nsj6njyzj3ppvrqtt36cp9xyydzqzumz82";

        PaymentTransaction paymentTransaction =
                PaymentTransaction.builder()
                        .sender(sender)
                        .receiver(receiver)
                        .amount(BigInteger.valueOf(3000))
                        .unit("57fca08abbaddee36da742a839f7d83a7e1d2419f1507fcbf3916522534245525259")
                        .build();

        long ttl = blockService.getLastestBlock().getValue().getSlot() + 1000;
        TransactionDetailsParams detailsParams =
                TransactionDetailsParams.builder()
                        .ttl(ttl)
                        .build();

        BigInteger fee = feeCalculationService.calculateFee(paymentTransaction, detailsParams
                , null);

        paymentTransaction.setFee(fee);

        Result<TransactionResult> result = transactionHelperService.transfer(paymentTransaction, detailsParams);

        if (result.isSuccessful())
            System.out.println("Transaction Id: " + result.getValue());
        else
            System.out.println("Transaction failed: " + result);

        System.out.println(transactionHelperService.getUtxoTransactionBuilder());

        waitForTransaction(result);
    }


    public static void main(String[] args) throws AddressExcepion, ApiException, CborSerializationException {
        new TransferTokenTest().transfer();
        System.exit(1);
    }
}
