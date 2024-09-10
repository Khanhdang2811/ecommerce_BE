package com.zosh.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
@Entity
public class ApiResponse 
{
		@Id
		@GeneratedValue(strategy = GenerationType.AUTO)
	 private Long id;
	  private boolean status;
	  private String message;
	  public ApiResponse()
	 {
	 }
	    
	  
	  public ApiResponse(boolean status, String message)
	  
	{
		this.status = status;
		this.message = message;
	}



	// getter và setter cho status và message

	  public boolean isStatus() {
		return status;
	}

	public void setStatus(boolean status) {
		this.status = status;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	

	
}
