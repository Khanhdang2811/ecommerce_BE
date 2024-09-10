package com.zosh.model;

public class PaymentDetails {
	
	private String paymentMethod;
	private String status;
	private String paymentld;
	private String paymentLinkId;
	private String paymentLinkReferenceld;
	private String paymentLinkStatus;
	private String paypalPaymentld;
	
	
	PaymentDetails()
	{
		//Todo
	}


	public String getPaymentMethod() {
		return paymentMethod;
	}


	public void setPaymentMethod(String paymentMethod) {
		this.paymentMethod = paymentMethod;
	}


	public String getStatus() {
		return status;
	}


	public void setStatus(String status) {
		this.status = status;
	}


	public String getPaymentld() {
		return paymentld;
	}


	public void setPaymentld(String paymentld) {
		this.paymentld = paymentld;
	}


	public String getPaymentLinkId() {
		return paymentLinkId;
	}


	public void setPaymentLinkId(String paymentLinkId) {
		this.paymentLinkId = paymentLinkId;
	}


	public String getPaymentLinkReferenceld() {
		return paymentLinkReferenceld;
	}


	public void setPaymentLinkReferenceld(String paymentLinkReferenceld) {
		this.paymentLinkReferenceld = paymentLinkReferenceld;
	}


	public String getPaymentLinkStatus() {
		return paymentLinkStatus;
	}


	public void setPaymentLinkStatus(String paymentLinkStatus) {
		this.paymentLinkStatus = paymentLinkStatus;
	}


	public String getPaypalPaymentld() {
		return paypalPaymentld;
	}


	public void setPaypalPaymentld(String paypalPaymentld) {
		this.paypalPaymentld = paypalPaymentld;
	}
	

	
}
