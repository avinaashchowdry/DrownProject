--Create table hosts to store the results from 
CREATE TABLE public."Hosts"
(
  "RANK" integer NOT NULL,
  "TLDOMAIN" varchar(20) NOT NULL,
  "DOMAIN" varchar(100) NOT NULL,
  "SSLSUPPORT" boolean NOT NULL,
  "TLSVERSION" varchar(8) NOT NULL,
  "SSLv2SUPPORT" boolean NOT NULL,
  "WEAKCIPHERS" boolean NOT NULL,
  "SHAREDCERTIFICATES" boolean NOT NULL,
  "DROWNVULNERABLE" boolean NOT NULL,
  CONSTRAINT pk PRIMARY KEY ("RANK")
)
WITH (
  OIDS=FALSE
);

--Create an index on Ranks column
CREATE UNIQUE INDEX "RankIndex"
  ON public."Hosts"
  USING btree
  ("RANK");