package com.idega.block.oauth2.server.authentication.bean;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import com.idega.block.login.bean.LoggedInUser;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class User extends LoggedInUser {

	private static final long serialVersionUID = 3109303153488234141L;

	private Address address;

	public User() {
		super();
	}

	public User(LoggedInUser loggedInUser) {
		this();

		if (loggedInUser != null) {
			setName(loggedInUser.getName());
			setPersonalID(loggedInUser.getPersonalID());
			setLogin(loggedInUser.getLogin());
			setToken(loggedInUser.getToken());
		}
	}

	public Address getAddress() {
		return address;
	}

	public void setAddress(Address address) {
		this.address = address;
	}

}