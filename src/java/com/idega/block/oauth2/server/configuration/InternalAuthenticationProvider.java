package com.idega.block.oauth2.server.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.idega.block.login.data.PasswordTokenEntity;
import com.idega.block.login.data.dao.PasswordTokenEntityDAO;
import com.idega.core.accesscontrol.business.LoginDBHandler;
import com.idega.core.accesscontrol.data.LoginTable;
import com.idega.presentation.IWContext;
import com.idega.user.dao.UserDAO;
import com.idega.user.data.bean.User;
import com.idega.util.CoreUtil;
import com.idega.util.expression.ELUtil;

@Component
public class InternalAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	private PasswordTokenEntityDAO passwordTokenEntityDAO;

	@Autowired
	private UserDAO userDao;

	public UserDAO getUserDao() {
		if (userDao == null)
			ELUtil.getInstance().autowire(this);
		return userDao;
	}

	public void setUserDao(UserDAO userDao) {
		this.userDao = userDao;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String providedLogin = authentication.getName();
		String token = null;
		Object request = authentication.getDetails();
		if (request instanceof Map) {
			Map<?, ?> details = (Map<?, ?>) request;
			token = (String) details.get("token");
		}
		if (token == null) {
			return null;
		}

		User user = null;
		PasswordTokenEntity entity = getPasswordTokenEntityDAO().findByToken(token);
		if (entity == null) {
			IWContext iwc = CoreUtil.getIWContext();
			user = iwc != null && iwc.isLoggedOn() ? iwc.getLoggedInUser() : null;
		} else {
			user = getUserDao().getUserByUUID(entity.getUuid());
		}

		if (user == null) {
			return null;
		}

		LoginTable loginTable = LoginDBHandler.getUserLogin(user.getId());
		return getAuthentication(loginTable, providedLogin);
	}

	public Authentication getAuthentication(LoginTable loginTable, String providedLogin) {
		if (loginTable == null) {
			return null;
		}

		String login = null;
		String password = null;

		login = loginTable.getUserLogin();
		if (login == null) {
			return null;
		}
		if (!login.equals(providedLogin)) {
			return null;
		}

		password = loginTable.getUserPasswordInClearText();
		if (password == null) {
			return null;
		}

		List<GrantedAuthority> grantedAuths = new ArrayList<>();
		grantedAuths.add(new SimpleGrantedAuthority("ROLE_APP"));
		org.springframework.security.core.userdetails.User loggedInUser = new org.springframework.security.core.userdetails.User(
				login, password, grantedAuths);
		Authentication auth = new UsernamePasswordAuthenticationToken(loggedInUser, password, grantedAuths);
		return auth;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

	public PasswordTokenEntityDAO getPasswordTokenEntityDAO() {
		if (passwordTokenEntityDAO == null)
			ELUtil.getInstance().autowire(this);
		return passwordTokenEntityDAO;
	}

	public void setPasswordTokenEntityDAO(PasswordTokenEntityDAO passwordTokenEntityDAO) {
		this.passwordTokenEntityDAO = passwordTokenEntityDAO;
	}
}
