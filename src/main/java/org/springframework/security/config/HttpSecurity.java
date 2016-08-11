package org.springframework.security.config;

import org.springframework.security.web.authentication.AuthenticationFailureHandler;

public class HttpSecurity {
	private FormLogin formLogin;

	public FormLogin formLogin() {
		if(this.formLogin == null) {
			this.formLogin = new FormLogin();
		}
		return formLogin;
	}

	FormLogin getFormLogin() {
		return formLogin;
	}

	public static class FormLogin {
		private String usernameParameter = "username";

		private String passwordParameter = "password";

		private AuthenticationFailureHandler failureHandler;

		public FormLogin failureHandler(AuthenticationFailureHandler failureHandler) {
			this.failureHandler = failureHandler;
			return this;
		}

		public FormLogin usernameParameter(String usernameParameter) {
			this.usernameParameter = usernameParameter;
			return this;
		}

		public FormLogin passwordParameter(String passwordParameter) {
			this.passwordParameter = passwordParameter;
			return this;
		}

		AuthenticationFailureHandler getFailureHandler() {
			return failureHandler;
		}

		String getPasswordParameter() {
			return passwordParameter;
		}

		String getUsernameParameter() {
			return usernameParameter;
		}
	}
}
