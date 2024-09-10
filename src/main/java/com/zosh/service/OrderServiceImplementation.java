package com.zosh.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.zosh.exception.OrderException;
import com.zosh.model.Address;
import com.zosh.model.Cart;
import com.zosh.model.CartItem;
import com.zosh.model.Order;
import com.zosh.model.OrderItem;
import com.zosh.model.User;
import com.zosh.repository.AddressRepository;
import com.zosh.repository.OrderItemRepository;
import com.zosh.repository.OrderRespository;
import com.zosh.repository.UserRepository;

@Service
public class OrderServiceImplementation implements OrderService{
	private OrderRespository orderResporsitory;
	private AddressRepository addressRepository;
	private UserRepository userRepository ;
	private OrderItemService orderItemService;
	private OrderItemRepository orderItemRespository;
	private CartService cartService;
	

	public OrderServiceImplementation(OrderRespository orderResporsitory,
			AddressRepository addressRepository,
			UserRepository userRepository,
			OrderItemService orderItemService,
			OrderItemRepository orderItemRespository,
			CartService cartService)
	{
		this.orderResporsitory = orderResporsitory;
		this.addressRepository = addressRepository;
		this.userRepository = userRepository;
		this.orderItemRespository = orderItemRespository;
		this.orderItemService = orderItemService;
		this.cartService = cartService;
		
	}
	@Override
	public Order createrOder(User user, Address shippingAdress) {

		shippingAdress.setUser(user);
		Address address = addressRepository.save(shippingAdress);
		user.getAddress().add(address);
		userRepository.save(user);
		Cart cart = cartService.findUserCart(user.getId());
		List<OrderItem> orderItems = new ArrayList<>();
		
		for(CartItem item:cart.getCartitems())
		{
			OrderItem orderItem =  new OrderItem();
			
			orderItem.setPrice(item.getPrice());
			orderItem.setProduct(item.getProduct());
			orderItem.setQuantity(item.getQuantity());
			orderItem.setSize(item.getSize());
			orderItem.setUserId(item.getUserId());
			orderItem.setDiscountedPrice(item.getDiscountedPrice());
			
			OrderItem createOrderItem = orderItemRespository.save(orderItem);
			
			orderItems.add(createOrderItem);	
		}
		
		Order createdOrder = new Order();
		createdOrder.setUser(user);
		createdOrder.setOderitems(orderItems);
		createdOrder.setTotalPrice(cart.getTotalPrice());
		createdOrder.setTotalDiscountedPrice(cart.getTotalDiscountedPrice());
		createdOrder.setDiscounte(cart.getDiscounte());
		createdOrder.setTotalitem(cart.getTotalItem());
		
		createdOrder.setShippingAdress(address);
		createdOrder.setOderDate(LocalDateTime.now());
		createdOrder.setOrderStatus("PENDING");
		createdOrder.getPaymenDetails().setStatus("PENDING");
		createdOrder.setCreateAt(LocalDateTime.now());
		
		Order savedOrder = orderResporsitory.save(createdOrder);
		
		for(OrderItem item:orderItems) 
		{
			item.setOrder(savedOrder);
			orderItemRespository.save(item);
			
		}
		
		
		return savedOrder;
	}

	@Override
	public Order findOrderById(Long orderld) throws OrderException {
		Optional<Order> opt = orderResporsitory.findById(orderld);
		
		if(opt.isPresent())
		{
			return opt.get();
		}
		throw new OrderException("Order not exist with id" + orderld );
	}

	@Override
	public List<Order> usersOrderHistory(Long userld) {
	List<Order> orders = orderResporsitory.getUsersOrders(userld);
	return orders;
	}

	@Override
	public Order placedOrder(Long orderld) throws OrderException {
		Order order = findOrderById(orderld);
		order.setOrderStatus("PLACED");
		order.getPaymenDetails().setStatus("COMPLETED");
		return order;
	}

	@Override
	public Order confirmedOrder(Long orderld) throws OrderException {
		Order order = findOrderById(orderld);
		order.setOrderStatus("CONFIRMED");
		return orderResporsitory.save(order);
	}

	@Override
	public Order shippedOrder(Long orderld) throws OrderException {
		Order order = findOrderById(orderld);
		order.setOrderStatus("DELIVERED");
		return orderResporsitory.save(order);		
	}

	@Override
	public Order deliveredOrder(Long orderld) throws OrderException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Order cancledOrder(Long orderld) throws OrderException {
		Order order = findOrderById(orderld);
		order.setOrderStatus("CANCELLED");
		return orderResporsitory.save(order);
	}

	@Override
	public List<Order> getAllOrders() {
		return orderResporsitory.findAll();
	}

	@Override
	public Order deleteOrder(Long orderld) throws OrderException {
		Order order = findOrderById(orderld);
		orderResporsitory.deleteById(orderld);
		return order;
	}

}
