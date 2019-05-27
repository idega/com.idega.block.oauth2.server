package com.idega.block.oauth2.server.authentication.business;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import com.idega.block.oauth2.server.authentication.bean.AuthorizationCredentials;

public interface Authenticator {

	public static final String 	PATH = "/authenticate",
								USER = "/user";

	public Response getAuthenticatedUser(AuthorizationCredentials credentials, HttpServletRequest request, HttpServletResponse response, ServletContext context);

}