package com.zosh.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.zosh.config.JwtProvider;
import com.zosh.exception.UserException;
import com.zosh.model.User;
import com.zosh.repository.UserRepository;

@Service
public class UserServiceImplementation implements UserService {

	private UserRepository userRepository;
	private JwtProvider jwtProvider;
	
	public UserServiceImplementation(UserRepository userRepository,JwtProvider jwtProvider)
	{
		this.userRepository = userRepository;
		this.jwtProvider = jwtProvider;
		
	}
	
	
	@Override
	public User findUserById(Long userid) throws UserException {
		Optional<User> user = userRepository.findById(userid);
		if(user.isPresent())
		{
			return user.get();
		}
		
		throw new UserException("user nor found with id: " +userid);
	}

	@Override
	public User findUserProfileByJwt(String jwt) throws UserException {
		String emai=jwtProvider.getEmailFromToken(jwt);
		
		User user = userRepository.findByEmail(emai);
		
		if(user == null)
		{
			throw new UserException("user not found with email: "  + emai);
		}
		
		return user;
	}

}
