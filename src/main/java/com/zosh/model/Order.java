package com.zosh.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

@Entity
@Table(name="orders")
public class Order {
	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Long id;
	
	@Column(name="order_id")
	private String ordered;
	
	@ManyToOne
	private User user;
	
	@OneToMany(mappedBy="order",cascade = CascadeType.ALL)
	private List<OrderItem>oderitems = new ArrayList<>();
	
	private LocalDateTime oderDate;
	
	private  LocalDateTime deliveryDate;
	
	@OneToOne
	private Address shippingAdress;
	
	@Embedded
	private PaymentDetails paymenDetails = new PaymentDetails();
	
	private String totalPrice;
	
	private Integer totalDiscountedPrice;
	
	private Integer discounte;
	
	private String orderStatus;
	
	private int totalitem;
	
	private LocalDateTime createdAt;
	
	public Order() 
	{
	}
	

	public Order(Long id, String ordered, User user, List<OrderItem> oderitem, LocalDateTime oderDate,
			LocalDateTime deliveryDate, Address shippingAdress, PaymentDetails paymenDetails, double totalPrice,
			Integer totalDiscountedPrice, Integer discounte, String orderStatus, int totalitem,
			LocalDateTime createAt) {
		super();
		this.id = id;
		this.ordered = ordered;
		this.user = user;
		this.oderitems = oderitem;
		this.oderDate = oderDate;
		this.deliveryDate = deliveryDate;
		this.shippingAdress = shippingAdress;
		this.paymenDetails = paymenDetails;
		this.totalPrice = String.valueOf(totalPrice);
		this.totalDiscountedPrice = totalDiscountedPrice;
		this.discounte = discounte;
		this.orderStatus = orderStatus;
		this.totalitem = totalitem;
		this.createdAt = createAt;
	}


	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getOrdered() {
		return ordered;
	}

	public void setOrdered(String ordered) {
		this.ordered = ordered;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public List<OrderItem> getOderitems() {
		return oderitems;
	}

	public void setOderitems(List<OrderItem> oderitem) {
		this.oderitems = oderitem;
	}

	public LocalDateTime getOderDate() {
		return oderDate;
	}

	public void setOderDate(LocalDateTime oderDate) {
		this.oderDate = oderDate;
	}

	public LocalDateTime getDeliveryDate() {
		return deliveryDate;
	}

	public void setDeliveryDate(LocalDateTime deliveryDate) {
		this.deliveryDate = deliveryDate;
	}

	public Address getShippingAdress() {
		return shippingAdress;
	}

	public void setShippingAdress(Address shippingAdress) {
		this.shippingAdress = shippingAdress;
	}

	public PaymentDetails getPaymenDetails() {
		return paymenDetails;
	}

	public void setPaymenDetails(PaymentDetails paymenDetails) {
		this.paymenDetails = paymenDetails;
	}

	public String getTotalPrice() {
		return totalPrice;
	}

	public void setTotalPrice(double totalPrice) {
		this.totalPrice = String.valueOf(totalPrice);
	}

	public Integer getTotalDiscountedPrice() {
		return totalDiscountedPrice;
	}

	public void setTotalDiscountedPrice(Integer totalDiscountedPrice) {
		this.totalDiscountedPrice = totalDiscountedPrice;
	}

	public Integer getDiscounte() {
		return discounte;
	}

	public void setDiscounte(Integer discounte) {
		this.discounte = discounte;
	}

	public String getOrderStatus() {
		return orderStatus;
	}

	public void setOrderStatus(String orderStatus) {
		this.orderStatus = orderStatus;
	}

	public int getTotalitem() {
		return totalitem;
	}

	public void setTotalitem(int totalitem) {
		this.totalitem = totalitem;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreateAt(LocalDateTime createAt) {
		this.createdAt = createAt;
	}
	
	
	

}

