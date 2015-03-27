These are some examples of useful queries to the download history database.


# Examples #

```

CREATE VIEW amico_summary AS 
   (SELECT DISTINCT timestamp,md5,host,file_size AS size,score,
       MAX(trusted_av_labels) AS tavs,MAX(num_av_labels) AS avs,
       corrupt,MAX(DATE(query_time)) AS vt_query 
    FROM pe_dumps JOIN amico_scores USING(dump_id) 
       LEFT JOIN virus_total_scans USING(md5) 
    GROUP BY timestamp,md5,host,size,score,corrupt 
    ORDER BY timestamp DESC);


SELECT * FROM amico_summary WHERE score > 0.4;

SELECT * FROM amico_summary WHERE host LIKE 'net.cloudfront.%' AND 
    (score>0.4 OR tavs>=2 OR avs>=5);

```


```
CREATE VIEW amico_details AS 
   (SELECT DISTINCT timestamp,md5,host,url,client,server,file_size AS size,score,
       MAX(trusted_av_labels) AS tavs,MAX(num_av_labels) AS avs,
       corrupt,MAX(DATE(query_time)) AS vt_query 
    FROM pe_dumps JOIN amico_scores USING(dump_id) 
       LEFT JOIN virus_total_scans USING(md5) 
    GROUP BY timestamp,md5,host,url,client,server,size,score,corrupt 
    ORDER BY timestamp DESC);

SELECT timestamp,md5,host,URL FROM amico_details 
    WHERE SUBSTRING(server::VARCHAR, '^[0-9]{1,3}\.[0-9]{1,3}') IN
    (SELECT SUBSTRING(bgp_prefix::VARCHAR, '[0-9]{1,3}\.[0-9]{1,3}') 
    FROM bgp2asn WHERE as_name ILIKE 'OVH%') 
    AND score > 0.5 ORDER BY timestamp DESC;

```