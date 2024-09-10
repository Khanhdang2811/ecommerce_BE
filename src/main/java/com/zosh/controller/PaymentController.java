package com.zosh.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.paypal.api.payments.Amount;
import com.paypal.api.payments.Details;
import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payee;
import com.paypal.api.payments.Payer;
import com.paypal.api.payments.Payment;
import com.paypal.api.payments.Transaction;
import com.paypal.base.rest.APIContext;
import com.paypal.base.rest.PayPalRESTException;
import com.zosh.exception.OrderException;
import com.zosh.model.Order;
import com.zosh.repository.OrderRespository;
import com.zosh.response.ApiResponse;
import com.zosh.service.OrderService;


@RestController
@RequestMapping("/api")
public class PaymentController {

  @Value("paypal.client.id")  
  private String clientId;

  @Value("paypal.client.secret")
  private String clientSecret;  

  @Autowired
  private OrderService orderService;

  @Autowired
  private OrderRespository orderRespository;
  
  @GetMapping("/pay")
  public ResponseEntity<PaymentLinkReponse> createPaymentLink(
      @PathVariable Long orderId, 
      @RequestHeader("Authorization")String jwt) 
          throws OrderException, PayPalRESTException {

    Order order = orderService.findOrderById(orderId);

    APIContext apiContext = new APIContext(clientId, clientSecret);    
    Links link = new Links();
    link.setMethod("GET");
    link.setRel("approve");
    link.setHref("http://localhost:3000/payment/" + orderId);

    Payee payee = new Payee();
    payee.setEmail(order.getUser().getEmail());

    Details details = new Details();
    details.setSubtotal("");
    details.setShipping("");
    details.setTax("");

    Amount amount = new Amount();
    amount.setCurrency("USD");
    amount.setTotal("");
    amount.setDetails(details);

    Transaction transaction = new Transaction();
    transaction.setAmount(amount);
    transaction.setDescription("Order payment");
    transaction.setPayee(payee);

    List<Transaction> transactions = new ArrayList<>();
    transactions.add(transaction);

    Payer payer = new Payer();
    payer.setPaymentMethod("paypal");

    Payment payment = new Payment();
    payment.setIntent("sale");
    payment.setPayer(payer);  
    payment.setTransactions(transactions);
    payment.setRedirectUrls(null);

    Payment createdPayment = payment.create(apiContext);
    String approvalLink = createdPayment.getLinks().get(1).getHref();
    PaymentLinkReponse res = new PaymentLinkReponse();
    res.setPayment_link_id(createdPayment.getId());
    res.setPayment_link_url(approvalLink);

    return new ResponseEntity<PaymentLinkReponse>(HttpStatus.CREATED);
  }

  @GetMapping("/payments")
  public ResponseEntity<ApiResponse> completePayment(
      @RequestParam(name = "paymentId") String paymentId, 
      @RequestParam(name = "orderId") Long orderId) 
          throws OrderException, PayPalRESTException {

    Order order = orderService.findOrderById(orderId);
    
    Payment payment = new Payment();
    if (payment.getState().equals("approved")) {
      order.getPaymenDetails().setPaymentld(paymentId);
      order.getPaymenDetails().setStatus("COMPLETED");
      order.setOrderStatus("PLACED");
      orderRespository.save(order);
    }

    ApiResponse response = new ApiResponse();
    response.setMessage("Your order has been placed");  
    response.setStatus(true);

    return new ResponseEntity<ApiResponse>(response, HttpStatus.ACCEPTED);
  }

}