package com.idega.block.oauth2.server.authentication.bean;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class Authentication {

	private String accessToken;

	private OAuth2Authentication authentication;

	public Authentication(String accessToken, OAuth2Authentication authentication) {
		this.accessToken = accessToken;
		this.authentication = authentication;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public OAuth2Authentication getAuthentication() {
		return authentication;
	}

	public void setAuthentication(OAuth2Authentication authentication) {
		this.authentication = authentication;
	}

}