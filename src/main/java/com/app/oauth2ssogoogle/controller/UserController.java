package com.app.oauth2ssogoogle.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
	
	@GetMapping(value = "/user")
	public Principal getSayHelloPrincipal(Principal principal) {
		return principal;
	}

}
