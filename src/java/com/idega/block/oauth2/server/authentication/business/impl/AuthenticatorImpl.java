package com.idega.block.oauth2.server.authentication.business.impl;

import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.idega.block.login.bean.OAuthToken;
import com.idega.block.login.business.OAuth2Service;
import com.idega.block.oauth2.server.authentication.bean.AccessToken;
import com.idega.block.oauth2.server.authentication.bean.Credentials;
import com.idega.block.oauth2.server.authentication.business.Authenticator;
import com.idega.core.accesscontrol.business.LoggedOnInfo;
import com.idega.core.accesscontrol.business.LoginBusinessBean;
import com.idega.core.accesscontrol.data.bean.UserLogin;
import com.idega.core.accesscontrol.event.LoggedInUserCredentials;
import com.idega.presentation.IWContext;
import com.idega.restful.business.DefaultRestfulService;
import com.idega.user.data.bean.User;
import com.idega.util.CoreUtil;
import com.idega.util.expression.ELUtil;

@Component
@Path(Authenticator.PATH)
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticatorImpl extends DefaultRestfulService implements Authenticator {

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
	@Path(Authenticator.USER)
	public Response getUser(
			Credentials credentials,
			@Context HttpServletRequest request
	) {
		if (credentials == null) {
			getLogger().warning("Credentials not provided");
			return getBadRequestResponse(Boolean.FALSE);
		}

		try {
			HttpSession session = request.getSession(true);

			LoginBusinessBean loginBusinessBean = LoginBusinessBean.getLoginBusinessBean(request);
			if (loginBusinessBean.isLoggedOn(request)) {
				IWContext iwc = CoreUtil.getIWContext();
				loginBusinessBean.logOutUser(iwc);
			}

			if (!loginBusinessBean.logInUser(request, credentials.getUsername(), credentials.getPassword())) {
				return getBadRequestResponse(Boolean.FALSE);
			}

			User user = loginBusinessBean.getCurrentUser(session);
			if (user == null) {
				return getBadRequestResponse(Boolean.FALSE);
			}

			LoggedOnInfo info = loginBusinessBean.getLoggedOnInfo(session, credentials.getUsername());
			if (info == null) {
				return getBadRequestResponse(Boolean.FALSE);
			}
			UserLogin login = info.getUserLogin();
			if (login == null) {
				return getBadRequestResponse(Boolean.FALSE);
			}
			Integer loginId = login.getId();
			if (loginId == null) {
				return getBadRequestResponse(Boolean.FALSE);
			}

			LoggedInUserCredentials loggedInUserCredentials = new LoggedInUserCredentials(
					request,
					credentials.getUrl(),
					credentials.getUsername(),
					credentials.getPassword(),
					null,
					loginId
			);
			OAuthToken token = getOAuth2Service().getToken(credentials.getClientId(), loggedInUserCredentials);
			if (token == null) {
				String message = "Failed to get access token";
				getLogger().warning(message);
				return getBadRequestResponse(message);
			}

			com.idega.block.oauth2.server.authentication.bean.User loggedInUserData = new com.idega.block.oauth2.server.authentication.bean.User();
			loggedInUserData.setName(user.getName());
			loggedInUserData.setAccessToken(new AccessToken(token, credentials.getUsername()));
			return getOKResponse(loggedInUserData);
		} catch (Exception e) {
			getLogger().log(Level.WARNING, "Error while logging in " + credentials.getUsername(), e);
		}

		return getInternalServerErrorResponse(Boolean.FALSE);
	}

}