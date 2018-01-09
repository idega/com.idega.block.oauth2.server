package com.idega.block.oauth2.server.authentication.bean;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import com.idega.block.login.bean.OAuthToken;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AccessToken implements Serializable {

	private static final long serialVersionUID = -5678966660215531673L;

	private OAuthToken token;

	private String user;

	public AccessToken() {
		super();
	}

	public AccessToken(OAuthToken token, String user) {
		super();

		this.token = token;
		this.user = user;
	}

	public OAuthToken getToken() {
		return token;
	}

	public void setToken(OAuthToken token) {
		this.token = token;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

}