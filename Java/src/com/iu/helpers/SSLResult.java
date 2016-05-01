package com.iu.helpers;

//Holds the result returned by the bash script 
public class SSLResult {
	private int rank;
	private String topLvlDomain;
	private String domain;
	private Boolean sslSupport;
	private String sslVersion;
	private Boolean sslv2Support;
	private Boolean weakCipher;
	private Boolean sharedCertificate;
	private Boolean drownVulnerable;

	public SSLResult(int rank, String topLvlDomain, String domain, Boolean sslSupport, String sslVersion,
			Boolean sslv2Support, Boolean weakCipher, Boolean sharedCertificate, Boolean drownVulnerable) {
		this.rank = rank;
		this.topLvlDomain = topLvlDomain;
		this.domain = domain;
		this.sslSupport = sslSupport;
		this.sslVersion = sslVersion;
		this.sslv2Support = sslv2Support;
		this.weakCipher = weakCipher;
		this.sharedCertificate = sharedCertificate;
		this.drownVulnerable = drownVulnerable;
	}

	public String toString() {
		String str;
		str = "Rank: " + rank + " Top-Level Domain: " + topLvlDomain + " Domain: " + domain + " SSLSupport:"
				+ sslSupport + " SSLVersion: " + sslVersion + " SSLV2 Support: " + sslv2Support
				+ " Weak Cipher Support: " + weakCipher + " Shared Certificates: " + sharedCertificate
				+ " Drown Vulnerable: " + drownVulnerable;
		return str;
	}

	public int getRank() {
		return rank;
	}

	public String getTopLvlDomain() {
		return topLvlDomain;
	}

	public String getDomain() {
		return domain;
	}

	public Boolean getSslSupport() {
		return sslSupport;
	}

	public String getSslVersion() {
		return sslVersion;
	}

	public Boolean getSslv2Support() {
		return sslv2Support;
	}

	public Boolean getWeakCipher() {
		return weakCipher;
	}

	public Boolean getSharedCertificate() {
		return sharedCertificate;
	}

	public Boolean getDrownVulnerable() {
		return drownVulnerable;
	}
}