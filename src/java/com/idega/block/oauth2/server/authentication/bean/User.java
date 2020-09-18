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

	private String fullName;

	private String email;

	private String mobilePhone;

	public User() {
		super();
	}

	public User(LoggedInUser loggedInUser) {
		this();

		if (loggedInUser != null) {
			setName(loggedInUser.getName());
			setFullName(getName());
			setPersonalID(loggedInUser.getPersonalID());
			setLogin(loggedInUser.getLogin());
			setToken(loggedInUser.getToken());
		}
	}

	public User(com.idega.user.data.bean.User user) {
		if (user != null) {
			setName(user.getName());
			setPersonalID(user.getPersonalID());
		}
	}

	public Address getAddress() {
		return address;
	}

	public void setAddress(Address address) {
		this.address = address;
	}

	public String getFullName() {
		return fullName;
	}

	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getMobilePhone() {
		return mobilePhone;
	}

	public void setMobilePhone(String mobilePhone) {
		this.mobilePhone = mobilePhone;
	}

}