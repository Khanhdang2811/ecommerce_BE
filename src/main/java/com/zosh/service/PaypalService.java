package com.zosh.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.paypal.api.payments.Amount;
import com.paypal.api.payments.Payer;
import com.paypal.api.payments.Payment;
import com.paypal.api.payments.PaymentExecution;
import com.paypal.api.payments.RedirectUrls;
import com.paypal.api.payments.Transaction;
import com.paypal.base.rest.APIContext;
import com.paypal.base.rest.PayPalRESTException;
import com.zosh.config.PaypalPaymentIntent;
import com.zosh.config.PaypalPaymentMethod;

@Service
public class PaypalService {
	@Autowired
	APIContext apiContext;
	
	public Payment createPayment(
	        Double total,
	        String currency,
	        PaypalPaymentMethod method,
	        PaypalPaymentIntent intent,
	        String description,
	        String cancelUrl,
	        String successUrl) throws PayPalRESTException {
		String totalAmount = String.format("%.2f", total).replace(",", ".");

	    // Create Amount object
	    Amount amount = new Amount();
	    amount.setCurrency(currency);
	    amount.setTotal(totalAmount);
	   
	    // Create Transaction object
	    Transaction transaction = new Transaction();
	    transaction.setDescription(description);
	    transaction.setAmount(amount);

	    // Create list of transactions
	    List<Transaction> transactions = new ArrayList<>();
	    transactions.add(transaction);

	    // Create Payer object
	    Payer payer = new Payer();
	    payer.setPaymentMethod(method.toString());

	    // Create Payment object
	    Payment payment = new Payment();
	    payment.setIntent(intent.toString());
	    payment.setPayer(payer);
	    payment.setTransactions(transactions);

	    // Create RedirectUrls object
	    RedirectUrls redirectUrls = new RedirectUrls();
	    redirectUrls.setCancelUrl(cancelUrl);
	    redirectUrls.setReturnUrl(successUrl);
	    payment.setRedirectUrls(redirectUrls);

	    // Set MaskRequestId to true
	    apiContext.setMaskRequestId(true);

	    // Return the created payment
	    return payment.create(apiContext);
	}

	
	public Payment executePayment(String paymentId, String payerId) throws PayPalRESTException{
		Payment payment = new Payment();
		payment.setId(paymentId);
		PaymentExecution paymentExecute = new PaymentExecution();
		paymentExecute.setPayerId(payerId);
		return payment.execute(apiContext, paymentExecute);
	}
}
