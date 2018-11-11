# Passwords  
I have working with passwords leaks for a while, and dealing with them is not
alwas fun due to multiple reason. They are often large, and takes time to load
in memory. The mix of strings in different format, such as utf-8, utf-16, ascii,
makes if hard to process. Therefore, the statistics we want to compute is end up
in a huge mess of error handling and memory management. 

I have to do it for living (at least for now), and so I decided to create this
cute little module to efficiently store and process the paassword leak
file. This library expects a clean password file, and it will not clean it for
you. It just makes life easy afterwards to process this file for other purposes.
Not sure how generic is the purpose, as I am the only one who is using it right now. 
All feedbacks are very welcome. 

## How to install?  
Dependencies:
* `numpy`
* `marisa_trie`

Downlload the readpw.py file into your main code and it should work. 


## How to use?
```ipython
In [1]: from readpw import Passwords

In [2]: ry = Passwords('/home/rahul/passwords/rockyou-withcount.txt.bz2')

In [3]: for id_, pw, f in ry.iterpws(10):
   ...:     print id_, pw, f
      ...: 
      3121838 123456 290729.0
      919221 12345 79076.0
      12769146 123456789 76789.0
      11327966 password 59462.0
      11789229 iloveyou 49952.0
      11389450 princess 33291.0
      6851250 1234567 21725.0
      8034161 rockyou 20901.0
      10680580 12345678 20553.0
      2902439 abc123 16648.0

In [5]: ry.sumvalues(10) # sums the frequency of most frequent 10 passwords.
Out[5]: 669126.0

In [6]: list(ry.sample_pws(10))
Out[6]: 
[u'lilmarvin09',
 u'evan*love',
 u'mylove',
 u'mmmsss',
 u'whudafxup?',
 u'123456',
 u'123456',
 u'beautiful',
 u'james123',
 u'foodie123']
         

```
