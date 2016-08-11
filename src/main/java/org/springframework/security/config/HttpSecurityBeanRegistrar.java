package org.springframework.security.config;

import java.util.List;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.HttpSecurity.FormLogin;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.web.context.support.StaticWebApplicationContext;

public class HttpSecurityBeanRegistrar {

	public static StaticWebApplicationContext create(HttpSecurity httpSecurity) {
		StaticWebApplicationContext context = new StaticWebApplicationContext();
		context.setServletConfig(new MockServletConfig());

		final BeanDefinitionRegistry registry = context;

		RootBeanDefinition filterChainMatcher = new RootBeanDefinition(AnyRequestMatcher.class);

		RootBeanDefinition securityContextFilter = new RootBeanDefinition(SecurityContextPersistenceFilter.class);

		List<BeanMetadataElement> filters = new ManagedList<>();
		filters.add(securityContextFilter);

		FormLogin formLogin = httpSecurity.getFormLogin();
		if(formLogin != null) {
			BeanDefinition authenticationManager = createAuthenticationManager();

			BeanDefinition usernamePasswordFilter = createUsernamePasswordAuthenticationManager(formLogin, authenticationManager);

			filters.add(usernamePasswordFilter);

			registry.registerBeanDefinition("authenticationManager", authenticationManager);
		}

		BeanDefinitionBuilder filterChain = BeanDefinitionBuilder.rootBeanDefinition(DefaultSecurityFilterChain.class);
		filterChain.addConstructorArgValue(filterChainMatcher);
		filterChain.addConstructorArgValue(filters);

		BeanDefinitionBuilder filterChainProxy = BeanDefinitionBuilder.rootBeanDefinition(FilterChainProxy.class);
		filterChainProxy.addConstructorArgValue(filterChain.getBeanDefinition());

		registry.registerBeanDefinition("springSecurityFilterChain", filterChainProxy.getBeanDefinition());

		context.refresh();
		return context;
	}

	private static BeanDefinition createUsernamePasswordAuthenticationManager(FormLogin formLogin, BeanDefinition authenticationManager) {
		BeanDefinitionBuilder usernamePasswordFilter = BeanDefinitionBuilder.rootBeanDefinition(UsernamePasswordAuthenticationFilter.class);
		usernamePasswordFilter.addPropertyValue("usernameParameter", formLogin.getUsernameParameter());
		usernamePasswordFilter.addPropertyValue("passwordParameter", formLogin.getPasswordParameter());
		usernamePasswordFilter.addPropertyValue("authenticationManager", authenticationManager);

		AuthenticationFailureHandler failureHandler = formLogin.getFailureHandler();
		if(failureHandler != null) {
			// FIXME: Programmatically register failureHandler as a Bean
			usernamePasswordFilter.addPropertyValue("authenticationFailureHandler", failureHandler);
		}
		return usernamePasswordFilter.getBeanDefinition();
	}

	private static BeanDefinition createAuthenticationManager() {
		List<BeanMetadataElement> users = createUsers();

		BeanDefinitionBuilder userDetailsService = createUserDetailsService(users);

		List<BeanMetadataElement> providers = createProviders(userDetailsService);

		BeanDefinitionBuilder authenticationManager = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
		authenticationManager.addConstructorArgValue(providers);

		return authenticationManager.getBeanDefinition();
	}

	private static List<BeanMetadataElement> createProviders(BeanDefinitionBuilder userDetailsService) {
		BeanDefinitionBuilder daoProvider = BeanDefinitionBuilder.rootBeanDefinition(DaoAuthenticationProvider.class);
		daoProvider.addPropertyValue("userDetailsService", userDetailsService.getBeanDefinition());

		List<BeanMetadataElement> providers = new ManagedList<>();
		providers.add(daoProvider.getBeanDefinition());
		return providers;
	}

	private static BeanDefinitionBuilder createUserDetailsService(List<BeanMetadataElement> users) {
		BeanDefinitionBuilder userDetailsService = BeanDefinitionBuilder
				.rootBeanDefinition(InMemoryUserDetailsManager.class);
		userDetailsService.addConstructorArgValue(users);
		return userDetailsService;
	}

	private static List<BeanMetadataElement> createUsers() {
		List<BeanMetadataElement> users = new ManagedList<>();
		BeanDefinitionBuilder authorities = BeanDefinitionBuilder
				.rootBeanDefinition(AuthorityUtils.class);
		authorities.addConstructorArgValue("ROLE_USER");
		authorities.setFactoryMethod("commaSeparatedStringToAuthorityList");
		BeanDefinitionBuilder user = BeanDefinitionBuilder
				.rootBeanDefinition(User.class);
		user.addConstructorArgValue("user");
		user.addConstructorArgValue("password");
		user.addConstructorArgValue(true);
		user.addConstructorArgValue(true);
		user.addConstructorArgValue(true);
		user.addConstructorArgValue(true);
		user.addConstructorArgValue(authorities.getBeanDefinition());
		users.add(user.getBeanDefinition());
		return users;
	}
}
