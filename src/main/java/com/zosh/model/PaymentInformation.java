package com.zosh.model;

import jakarta.persistence.Column;

public class PaymentInformation {
	
	@Column(name="cardholder_name")
	private String cardholderName;
	
	@Column(name="cardh_number")
	private String cardNumber;
	
	@Column(name="expirartion_date")
	private String expirationDate;
	
	@Column(name="cvv")
	private String cvv;
}
