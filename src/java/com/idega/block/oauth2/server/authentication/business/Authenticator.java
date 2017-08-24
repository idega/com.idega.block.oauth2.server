package com.idega.block.oauth2.server.authentication.business;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import com.idega.block.oauth2.server.authentication.bean.Credentials;

public interface Authenticator {

	public static final String 	PATH = "/authenticate",
								USER = "/user";

	public Response getUser(Credentials credentials, HttpServletRequest request);

}