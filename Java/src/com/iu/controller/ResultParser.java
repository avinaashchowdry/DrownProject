package com.iu.controller;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import com.iu.data.InsertionHandler;
import com.iu.helpers.SSLResult;	

public class ResultParser {

	private HashSet<Integer> ranks;
	private List<SSLResult> data; 
	
	public ResultParser() {
		 ranks = new HashSet<>();
		 data = new ArrayList<>();
	}

	//Reads the specified files from the resources directory 
	public void readFiles() {
		String resourcePath = "./Resources/";
		//The result files from 20 instances of Amazon Web Services
		String[] fileNames = {"result1.csv", "result2.csv" ,
				"result3.csv" , "result4.csv" , 
				"result5.csv" , "result6.csv" , 
				"result7.csv" , "result8.csv" , 
				"result9.csv" , "result10.csv" ,
				"result11.csv", "result12.csv" , 
				"result13.csv" , "result14.csv" , 
				"result15.csv" , "result16.csv" , 
				"result17.csv" , "result18.csv" , 
				"result19.csv" , "result20.csv"};
		
		for (String fileName: fileNames) {
			System.out.println(" Processing file: " + fileName);
			readFile(resourcePath + fileName);
			clearRanks();
		}
	}

	//Reads the file and adds the rows to database
	public void readFile(String fileName) {
		BufferedReader br = null;
		String line = "";
		String split = ",";

		try {
			br = new BufferedReader(new FileReader(fileName));
			while ((line = br.readLine()) != null) {
				if(! line.contains("port 443")) {
					String[] contents = line.split(split);
					SSLResult result =  parseLine(contents);
					if(!ranks.contains(result.getRank())) {
						ranks.add(result.getRank());
						data.add(result);
					}

					if(data.size() >= 5000) {
						insertData();
						data.clear();
					}
				}
			}

			if(data.size() > 0) {
				insertData();
				data.clear();
			}
		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if(br != null) {
				try {
					br.close();
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	//Clears the stored rank values
	public void clearRanks() {
		if(ranks.size() > 50000) {
			ranks.clear();
		}
	}

	//Inserts data to database
	public void insertData() {
		InsertionHandler ih = new InsertionHandler();
		ih.insertData(data);
	}

	//Parses the given line and stores it in SSLResult object
	public SSLResult parseLine(String[] contents) {
		SSLResult result;
		int rank = Integer.parseInt(contents[0].trim());
		Boolean sslSupport = contents[3].trim().equals("YES") ? true : false;
		Boolean sslv2 = contents[5].trim().equals("YES") ? true : false;
		Boolean weakCipher = contents[6].trim().equals("YES") ? true : false;
		Boolean sharedCertificate = contents[7].trim().equals("YES") ? true : false;
		Boolean drownVulnerable = contents[8].trim().equals("YES") ? true : false;
		String TLDVersion = contents[1].trim();

		if(TLDVersion.length() > 10) {
			int index = TLDVersion.indexOf(".");
			if(index > 0) {
				TLDVersion = TLDVersion.substring(index + 1,  TLDVersion.length());
			}
		}

		result = new SSLResult(rank, TLDVersion, contents[2].trim(), sslSupport, contents[4].trim(), sslv2, weakCipher, sharedCertificate, drownVulnerable);
		return result;
	}
}