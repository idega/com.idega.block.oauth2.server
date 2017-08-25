package com.idega.block.oauth2.server.authentication.bean;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import com.idega.block.login.bean.UserCredentials;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthorizationCredentials extends UserCredentials {

	private static final long serialVersionUID = -7370764883161301819L;

}