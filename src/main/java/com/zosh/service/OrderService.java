package com.zosh.service;

import java.util.List;

import com.zosh.exception.OrderException;
import com.zosh.model.Address;
import com.zosh.model.Order;
import com.zosh.model.User;

public interface OrderService {
	
	public Order createrOder(User user,Address shippingAdress);
	public Order findOrderById(Long orderld) throws OrderException;
	public List<Order> usersOrderHistory (Long userld);
	public Order placedOrder(Long orderld) throws OrderException;
	public Order confirmedOrder(Long orderld)throws OrderException;
	public Order shippedOrder(Long orderld) throws OrderException;
	public Order deliveredOrder(Long orderld) throws OrderException;
	public Order cancledOrder(Long orderld) throws OrderException;
	public List<Order>getAllOrders();
	public Order deleteOrder(Long orderld) throws OrderException;
	
	

}
