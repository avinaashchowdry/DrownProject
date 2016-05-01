package com.iu.data;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import com.iu.helpers.SSLResult;

public class InsertionHandler {

	Connection conn;
	
	public InsertionHandler() { 
		try {
			conn = DBConnection.getConnection();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public void insertData(List<SSLResult> data) {
		String sql = "INSERT INTO public.\"Hosts\"( \"RANK\", \"TLDOMAIN\", \"DOMAIN\", \"SSLSUPPORT\", "
				+ "\"TLSVERSION\", \"SSLv2SUPPORT\", \"WEAKCIPHERS\", \"SHAREDCERTIFICATES\", \"DROWNVULNERABLE\") VALUES" ;
		String values = "";

		for (SSLResult row : data) {
			values += " (" + row.getRank() + ", '" + row.getTopLvlDomain() + "', '"+ row.getDomain() + "', " + row.getSslSupport() 
			 + ", '" + row.getSslVersion() + "', "  + row.getSslv2Support() + ", " + row.getWeakCipher() + ", " + row.getSharedCertificate()
			 + ", " + row.getDrownVulnerable() + "),";
		}

		//Remove the last comma and append semicolon at the end 
		values = values.substring(0, values.length()-1);
		sql += values + ";";

		try {
			Statement st = conn.createStatement();
			st.executeUpdate(sql);
			conn.commit();
			st.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		finally {
			DBConnection.CloseConnection();
		}
	}
}