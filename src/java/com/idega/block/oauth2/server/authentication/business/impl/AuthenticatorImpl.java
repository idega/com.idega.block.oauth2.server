package com.idega.block.oauth2.server.authentication.business.impl;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.idega.block.login.bean.OAuthToken;
import com.idega.block.login.business.OAuth2Service;
import com.idega.block.oauth2.server.authentication.bean.Credentials;
import com.idega.block.oauth2.server.authentication.business.Authenticator;
import com.idega.core.accesscontrol.event.LoggedInUserCredentials;
import com.idega.restful.business.DefaultRestfulService;
import com.idega.util.expression.ELUtil;

@Component
@Path(Authenticator.PATH)
public class AuthenticatorImpl extends DefaultRestfulService implements
		Authenticator {

	@Autowired
	private OAuth2Service oAuth2Service;

	private OAuth2Service getOAuth2Service() {
		if (this.oAuth2Service == null) {
			ELUtil.getInstance().autowire(this);
		}

		return this.oAuth2Service;
	}

	@Override
	@POST
	public Response getUser(Credentials credentials) {
		if (credentials == null) {
			return null;
		}

		LoggedInUserCredentials loggedInUserCredentials = new LoggedInUserCredentials(
				null, credentials.getUrl(), credentials.getUsername(),
				credentials.getPassword(), null, null);
		OAuthToken token = getOAuth2Service().getToken(
				credentials.getClientId(), loggedInUserCredentials);
		if (token == null) {
			String message = "Failed to get access token";
			getLogger().warning(message);
			return getBadRequestResponse(message);
		}

		return getOKResponse(token);
	}

}
