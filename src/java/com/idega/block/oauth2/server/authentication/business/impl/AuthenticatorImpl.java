package com.idega.block.oauth2.server.authentication.business.impl;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.idega.block.login.bean.LoggedInUser;
import com.idega.block.login.business.OAuth2Service;
import com.idega.block.oauth2.server.authentication.bean.AuthorizationCredentials;
import com.idega.block.oauth2.server.authentication.bean.User;
import com.idega.block.oauth2.server.authentication.business.AdditionalDataDAO;
import com.idega.block.oauth2.server.authentication.business.Authenticator;
import com.idega.presentation.IWContext;
import com.idega.restful.business.DefaultRestfulService;
import com.idega.util.expression.ELUtil;

@Component
@Path(Authenticator.PATH)
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
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

	@Autowired(required = false)
	private AdditionalDataDAO additionalDataDAO;

	private AdditionalDataDAO getAdditionalDataDAO() {
		if (this.additionalDataDAO == null) {
			ELUtil.getInstance().autowire(this);
		}

		return this.additionalDataDAO;
	}

	@Override
	@POST
	@Path(Authenticator.USER)
	public Response getAuthenticatedUser(
			AuthorizationCredentials credentials,
			@Context HttpServletRequest request,
			@Context HttpServletResponse response,
			@Context ServletContext context
	) {
		IWContext iwc = new IWContext(request, response, context);
		LoggedInUser loggedInUserData = getOAuth2Service().getAuthenticatedUser(iwc, credentials);
		if (loggedInUserData == null) {
			return getBadRequestResponse(Boolean.FALSE);
		}

		User user = new User(loggedInUserData);

		if (getAdditionalDataDAO() != null) {
			user = getAdditionalDataDAO().getUser(loggedInUserData);
		}
		return getOKResponse(user);
	}

}