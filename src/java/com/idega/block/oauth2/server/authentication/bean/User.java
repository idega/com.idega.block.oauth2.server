package com.idega.block.oauth2.server.authentication.bean;

import java.io.Serializable;

public class User implements Serializable {

	private static final long serialVersionUID = 3109303153488234141L;

	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}