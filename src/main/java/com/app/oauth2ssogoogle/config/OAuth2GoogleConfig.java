package com.app.oauth2ssogoogle.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configurable
@EnableWebSecurity
public class OAuth2GoogleConfig extends WebSecurityConfigurerAdapter{

	@Autowired
	OAuth2ClientContext oAuth2ClientContext;
	
	@Autowired
	AuthorizationCodeResourceDetails authorizationCodeResourceDetails;
	
	@Autowired
	ResourceServerProperties resourceServerProperties;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
	}
	
	@Override
	public void configure(WebSecurity web)throws Exception {
		super.configure(web);
	}
	
	/** oauth2 google filter **/
	private OAuth2ClientAuthenticationProcessingFilter filter() {
		// Creating the filter for "/google/login" url
		OAuth2ClientAuthenticationProcessingFilter oAuth2Filter = new OAuth2ClientAuthenticationProcessingFilter(
				"/google/login");

		// Creating the rest template for getting connected with OAuth service.
		// The configuration parameters will inject while creating the bean.
		OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails,
				oAuth2ClientContext);
		oAuth2Filter.setRestTemplate(oAuth2RestTemplate);

		// setting the token service. It will help for getting the token and
		// user details from the OAuth Service
		oAuth2Filter.setTokenServices(new UserInfoTokenServices(resourceServerProperties.getUserInfoUri(),
				resourceServerProperties.getClientId()));

		return oAuth2Filter;
	}
	
	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception{
		httpSecurity.authorizeRequests()
			.antMatchers("/", 
					"/**.html", 
					"/**.js", 
					"/**.css", 
					"/node_modules/**", 
					"/js/**").permitAll()
			.anyRequest().fullyAuthenticated()
			.and()
			.logout()
			.logoutSuccessUrl("/").permitAll()
			.and()
			.addFilterAt(filter(), BasicAuthenticationFilter.class)
			.csrf()
			.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
			
	}
}
