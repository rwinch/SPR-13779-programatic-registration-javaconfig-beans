package com.example;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.Test;
import org.springframework.security.config.HttpSecurity;
import org.springframework.security.config.HttpSecurityBeanRegistrar;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.ConfigurableWebApplicationContext;

public class HttpSecurityTests {

	@Test
	public void usernamePasswordParameter() throws Exception {
		HttpSecurity http = new HttpSecurity();
		http
			.formLogin();

		try(ConfigurableWebApplicationContext context = HttpSecurityBeanRegistrar.create(http)) {

			FilterChainProxy springSecurityFilterChain = context.getBean(FilterChainProxy.class);
			MockMvc mockMvc = MockMvcBuilders
					.standaloneSetup(new TheController())
					.addFilter(springSecurityFilterChain)
					.build();

			mockMvc
				.perform(formLogin())
				.andExpect(authenticated().withUsername("user"));

			mockMvc
				.perform(formLogin().password("invalid"))
				.andExpect(unauthenticated());
		}
	}

	@Test
	public void customFailureHandler() throws Exception {
		HttpSecurity http = new HttpSecurity();
		http
			.formLogin()
				.failureHandler((request, response, exception) -> response.setStatus(401))
				.usernameParameter("username")
				.passwordParameter("password");

		try(ConfigurableWebApplicationContext context = HttpSecurityBeanRegistrar.create(http)) {

			FilterChainProxy springSecurityFilterChain = context.getBean(FilterChainProxy.class);
			MockMvc mockMvc = MockMvcBuilders
					.standaloneSetup(new TheController())
					.addFilter(springSecurityFilterChain)
					.build();
			mockMvc
				.perform(formLogin().password("invalid"))
				.andExpect(status().isUnauthorized());
		}
	}

	@Test
	public void j_usernamePasswordParameter() throws Exception {
		HttpSecurity http = new HttpSecurity();
		http
			.formLogin()
				.usernameParameter("j_username")
				.passwordParameter("j_password");

		try(ConfigurableWebApplicationContext context = HttpSecurityBeanRegistrar.create(http)) {
			FilterChainProxy springSecurityFilterChain = context.getBean(FilterChainProxy.class);
			MockMvc mockMvc = MockMvcBuilders
					.standaloneSetup(new TheController())
					.addFilter(springSecurityFilterChain)
					.build();

			mockMvc
				.perform(formLogin().userParameter("j_username").passwordParam("j_password"))
				.andExpect(authenticated().withUsername("user"));
		}
	}

	@RestController
	static class TheController {
		@RequestMapping("/")
		String index() {
			return "Home";
		}
	}
}
