package com.idega.block.oauth2.server.authentication.business;

import com.idega.block.login.bean.LoggedInUser;
import com.idega.block.oauth2.server.authentication.bean.User;

public interface AdditionalDataDAO {

	public static final String BEAN_NAME = "additionalDataDAO";

	public User getUser(LoggedInUser loggedInUser);

}
