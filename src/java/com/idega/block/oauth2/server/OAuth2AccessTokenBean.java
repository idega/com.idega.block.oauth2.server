package com.idega.block.oauth2.server;

import java.util.Date;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

import com.idega.block.login.bean.OAuthToken;

public class OAuth2AccessTokenBean extends OAuthToken {

	private static final long serialVersionUID = -4482551180431033996L;

	public OAuth2AccessTokenBean() {
		super();
	}

	public OAuth2AccessTokenBean(OAuth2AccessToken accessToken, AuthorizationRequest authorizationRequest) {
		this();

		if (accessToken != null) {
			setAccess_token(accessToken.getValue());
			setToken_type(accessToken.getTokenType());
			setRefresh_token(accessToken.getRefreshToken().getValue());

			Date expiration = accessToken.getExpiration();
			if (expiration != null) {
				long expires_in = (expiration.getTime() - System.currentTimeMillis()) / 1000;
				setExpires_in(Long.valueOf(expires_in).intValue());
			}
			String originalScope = authorizationRequest.getRequestParameters().get(OAuth2Utils.SCOPE);
			if (originalScope == null || !OAuth2Utils.parseParameterList(originalScope).equals(accessToken.getScope())) {
				setScope(OAuth2Utils.formatParameterList(accessToken.getScope()));
			}
		}
	}

}