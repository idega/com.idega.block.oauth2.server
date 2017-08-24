package com.idega.block.oauth2.server.authentication.bean;

import java.io.Serializable;
import java.util.Locale;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import com.idega.core.location.data.bean.Country;
import com.idega.core.location.data.bean.PostalCode;
import com.idega.util.CoreConstants;
import com.idega.util.StringUtil;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Address implements Serializable {

	private static final long serialVersionUID = -7729378574617947532L;

	private String streetAddress;
	private Integer postalCodeId;
	private String postalCode;
	private String city;
	private Integer countryId;
	private String country;

	private String fullAddress;

	public Address() {
		super();
	}

	public Address(com.idega.core.location.data.bean.Address address, Locale locale) {
		this();

		if (address != null) {
			PostalCode postalCode = address.getPostalCode();
			Country country = address.getCountry();
			initialize(
					address.getStreetAddress(),
					address.getCity(),
					postalCode == null ? null : postalCode.getPostalCode(),
					country == null ? null : country.getName(locale),
					country == null ? null : country.getId(),
					postalCode == null ? null : postalCode.getId()
			);
		}
	}

	public Address(com.idega.core.location.data.Address address, Locale locale) {
		this();

		if (address != null) {
			com.idega.core.location.data.PostalCode postalCode = address.getPostalCode();
			com.idega.core.location.data.Country country = address.getCountry();
			initialize(
					address.getStreetAddress(),
					address.getCity(),
					postalCode == null ? null : postalCode.getPostalCode(),
					country == null ? null : country.getName(locale),
					country == null ? null : Integer.valueOf(country.getPrimaryKey().toString()),
					postalCode == null ? null : Integer.valueOf(postalCode.getPrimaryKey().toString())
			);
		}
	}

	public Address(String streetAddress, String city, String postalCode, String country) {
		this();

		initialize(streetAddress, city, postalCode, country, null, null);
	}

	private void initialize(String streetAddress, String city, String postalCode, String country, Integer countryId, Integer postalCodeId) {
		setStreetAddress(streetAddress);
		setCity(city);
		setPostalCode(postalCode);
		setCountry(country);
		setCountryId(countryId);
		setPostalCodeId(postalCodeId);

		StringBuilder addressLabel = new StringBuilder();
		if (!StringUtil.isEmpty(getStreetAddress())) {
			addressLabel.append(getStreetAddress());

			if (!StringUtil.isEmpty(getPostalCode())) {
				addressLabel.append(CoreConstants.COMMA);
				addressLabel.append(CoreConstants.SPACE);
				addressLabel.append(getPostalCode());
			}

			if (!StringUtil.isEmpty(getCity())) {
				addressLabel.append(CoreConstants.SPACE);
				addressLabel.append(getCity());
			}

			if (!StringUtil.isEmpty(getCountry())) {
				addressLabel.append(CoreConstants.COMMA);
				addressLabel.append(CoreConstants.SPACE);
				addressLabel.append(getCountry());
			}
		}
		setFullAddress(addressLabel.toString());
	}

	public String getStreetAddress() {
		return streetAddress;
	}

	public void setStreetAddress(String streetAddress) {
		this.streetAddress = streetAddress;
	}

	public Integer getPostalCodeId() {
		return postalCodeId;
	}

	public void setPostalCodeId(Integer postalCodeId) {
		this.postalCodeId = postalCodeId;
	}

	public String getPostalCode() {
		return postalCode;
	}

	public void setPostalCode(String postalCode) {
		this.postalCode = postalCode;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public Integer getCountryId() {
		return countryId;
	}

	public void setCountryId(Integer countryId) {
		this.countryId = countryId;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}

	public String getFullAddress() {
		return fullAddress;
	}

	public void setFullAddress(String fullAddress) {
		this.fullAddress = fullAddress;
	}

}