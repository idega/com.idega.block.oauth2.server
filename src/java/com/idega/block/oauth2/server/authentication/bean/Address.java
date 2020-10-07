package com.idega.block.oauth2.server.authentication.bean;

import java.io.Serializable;
import java.util.Locale;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

import com.idega.core.location.business.AddressBusinessBean;
import com.idega.core.location.data.Commune;
import com.idega.core.location.data.CommuneHome;
import com.idega.core.location.data.CountryHome;
import com.idega.core.location.data.bean.Country;
import com.idega.core.location.data.bean.PostalCode;
import com.idega.data.IDOLookup;
import com.idega.idegaweb.IWMainApplication;
import com.idega.idegaweb.IWMainApplicationSettings;
import com.idega.util.CoreConstants;
import com.idega.util.StringHandler;
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
	private String computedFullAddress;

	public Address() {
		super();
	}

	public Address(com.idega.core.location.data.bean.Address address, Locale locale) {
		this();

		if (address != null) {
			PostalCode postalCode = address.getPostalCode();
			Country country = address.getCountry();
			Country countryFromPostalCode = null;
			String cityFromPostalCode = null;
			if (postalCode != null) {
				countryFromPostalCode = postalCode.getCountry();
				cityFromPostalCode = postalCode.getName();
			}
			initialize(
					address.getStreetAddress(),
					StringUtil.isEmpty(address.getCity()) ? cityFromPostalCode : address.getCity(),
					postalCode == null ? null : postalCode.getPostalCode(),
					country == null ? countryFromPostalCode == null ? null : countryFromPostalCode.getName(locale) : country.getName(locale),
					country == null ? countryFromPostalCode == null ? null : countryFromPostalCode.getId() : country.getId(),
					postalCode == null ? null : postalCode.getId(),
					locale
			);
		}
	}

	public Address(com.idega.core.location.data.Address address, Locale locale) {
		this();

		if (address != null) {
			com.idega.core.location.data.PostalCode postalCode = address.getPostalCode();
			com.idega.core.location.data.Country country = address.getCountry();
			com.idega.core.location.data.Country countryFromPostalCode = null;
			String cityFromPostalCode = null;
			if (postalCode != null) {
				countryFromPostalCode = postalCode.getCountry();
				cityFromPostalCode = postalCode.getName();
			}
			initialize(
					address.getStreetAddress(),
					StringUtil.isEmpty(address.getCity()) ? cityFromPostalCode : address.getCity(),
					postalCode == null ? null : postalCode.getPostalCode(),
					country == null ? countryFromPostalCode == null ? null : countryFromPostalCode.getName(locale) : country.getName(locale),
					country == null ? countryFromPostalCode == null ? null : Integer.valueOf(countryFromPostalCode.getPrimaryKey().toString()) : Integer.valueOf(country.getPrimaryKey().toString()),
					postalCode == null ? null : Integer.valueOf(postalCode.getPrimaryKey().toString()),
					locale
			);
		}
	}

	public Address(String streetAddress, String city, String postalCode, String country) {
		this();

		initialize(streetAddress, city, postalCode, country, null, null, null);
	}

	private void initialize(String streetAddress, String city, String postalCode, String country, Integer countryId, Integer postalCodeId, Locale locale) {
		setStreetAddress(streetAddress);
		setCity(city);
		setPostalCode(postalCode);
		setCountry(country);
		setCountryId(countryId);
		setPostalCodeId(postalCodeId);

		StringBuilder addressLabel = new StringBuilder();
		if (!StringUtil.isEmpty(getStreetAddress())) {
			addressLabel.append(getStreetAddress());

			IWMainApplicationSettings settings = IWMainApplication.getDefaultIWMainApplication().getSettings();

			if (settings.getBoolean("add_postal_to_address_label", true)) {
				if (!StringUtil.isEmpty(getPostalCode())) {
					addressLabel.append(CoreConstants.COMMA);
					addressLabel.append(CoreConstants.SPACE);
					addressLabel.append(getPostalCode());
				}
			}

			if (settings.getBoolean("add_city_to_address_label", true)) {
				if (!StringUtil.isEmpty(getCity())) {
					addressLabel.append(CoreConstants.SPACE);
					addressLabel.append(getCity());
				}
			}

			if (settings.getBoolean("add_country_to_address_label", true)) {
				String locCountry = null;
				if (countryId != null) {
					try {
						CountryHome countryHome = (CountryHome) IDOLookup.getHome(com.idega.core.location.data.Country.class);
						com.idega.core.location.data.Country countryEntity = countryHome.findByPrimaryKey(countryId);
						locCountry = countryEntity.getLocalizedName(locale);
					} catch (Exception e) {}
				}

				if (!StringUtil.isEmpty(country) || !StringUtil.isEmpty(locCountry)) {
					addressLabel.append(CoreConstants.COMMA);
					addressLabel.append(CoreConstants.SPACE);
					addressLabel.append(StringUtil.isEmpty(locCountry) ? country : locCountry);
				}
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

	public String getComputedFullAddress() {
		if (StringUtil.isEmpty(computedFullAddress)) {
			String fullAddress = CoreConstants.EMPTY;

			String streetAddress = getStreetAddress();
			fullAddress = fullAddress.concat(StringUtil.isEmpty(streetAddress) ? AddressBusinessBean.NOT_AVAILABLE : streetAddress).concat(CoreConstants.SEMICOLON);

			String postalCode = getPostalCode();
			String city = getCity();
			fullAddress = fullAddress.concat(StringUtil.isEmpty(city) || StringUtil.isEmpty(postalCode) ?
					AddressBusinessBean.NOT_AVAILABLE :
					postalCode.concat(CoreConstants.SPACE).concat(city)).concat(CoreConstants.SEMICOLON);

			String countryName = null, countryISO = null;
			Integer countryId = getCountryId();
			countryId = countryId == null ?
					StringHandler.isNumeric(getCountry()) ? Integer.valueOf(getCountry()) : null :
					countryId;
			try {
				CountryHome countryHome = (CountryHome) IDOLookup.getHome(com.idega.core.location.data.Country.class);
				com.idega.core.location.data.Country country = countryId == null ?
						countryHome.findByCountryName(getCountry()) :
						countryHome.findByPrimaryKey(countryId);
				countryName = country.getName();
				countryISO = country.getIsoAbbreviation();
			} catch (Exception e) {}
			fullAddress = fullAddress.concat(StringUtil.isEmpty(countryName) || StringUtil.isEmpty(countryISO) ?
					AddressBusinessBean.NOT_AVAILABLE :
					countryName.concat(CoreConstants.COLON).concat(countryISO)).concat(CoreConstants.SEMICOLON);

			String communeName = null, communeCode = null;
			if (!StringUtil.isEmpty(city)) {
				try {
					CommuneHome communeHome = (CommuneHome) IDOLookup.getHome(Commune.class);
					Commune commune = null;
					try {
						commune = communeHome.findByCommuneName(city);
					} catch (Exception e) {}
					if (commune == null) {
						commune = communeHome.create();
						commune.setCommuneName(city);
						commune.setIsDefault(false);
						commune.store();
					} else {
						communeName = commune.getCommuneName();
						communeCode = commune.getCommuneCode();
					}
					if (StringUtil.isEmpty(communeName)) {
						commune.setCommuneName(city);
					}
					if (StringUtil.isEmpty(communeCode)) {
						communeCode = commune.getPrimaryKey().toString();
						commune.setCommuneCode(communeCode);
					}
					commune.store();
				} catch (Exception e) {}
			}
			fullAddress = fullAddress.concat(StringUtil.isEmpty(communeName) || StringUtil.isEmpty(communeCode) ? AddressBusinessBean.NOT_AVAILABLE : communeName.concat(CoreConstants.COLON).concat(communeCode));

			this.computedFullAddress = fullAddress;
		}
		return computedFullAddress;
	}

	public void setComputedFullAddress(String computedFullAddress) {
		this.computedFullAddress = computedFullAddress;
	}

}