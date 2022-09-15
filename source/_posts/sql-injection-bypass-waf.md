---
title: sql注入之waf绕过篇 
tags: 
- sql
- ctf
- php
categories: 
- web安全
---



***SQL注入原理***：Sql 注入攻击是指在数据库交互的参数位置写入恶意sql语句，由于未对数据进行过滤或过滤不严格便带入数据库中解析执行，最后返回执行敏感数据，它目前黑客对数据库进行攻击的最常用手段之一。

##### SQL注入的根本原因：字符串与sql语句未从根本上区分开，导致输入的字符串被当做sql语句解析。

下面分享几种常见的[SQL注入](https://so.csdn.net/so/search?q=SQL注入&spm=1001.2101.3001.7020)常见绕过方法：以下以 **index.php?id=1** 为例绕过

> ## 0x00 大小写绕过

例如当后台对select进行了过滤时，利用**php对大小写敏感，但mysql中对大小写不敏感**的特性，常见的replace(‘select’,’’)取代函数,则payload：

``` java
index.php?id=-1 Union SeleCt 1,2,3
```

> ## 0x01 双写绕过

原理同大小写类似，若后台用if语句对传入的参数进行检测是否传入slelect时，可以payload：

``` java
index.php?id=-1 and ununionion selselectect 1,2,3
```

当经过过滤后replace('select','',$id)，语句则变成了index.php?id=-1 union select 1,2,3达到绕过

> ##  0x02 编码

常见编码方式
1，URL 编码(双重url编码)
2，Unicode 编码
3，十六进制编码
4，其他后端会解析的编码
例如对admin URL编码后 %61%64%6D%69%6E，因此payload:

```JAVA
index.php?id=-1 union select 1,2,password from users where username=%61%64%6D%69%6E
```

> ##  0x03 关键字替换或等价函数替换

hex()、bin() --> ascii()
sleep() -->benchmark()
concat_ws() --> group_concat()
mid()、substr() --> substring()
@@user --> user()
对于and,or的绕过其实还可以尝试一下&&,||
注意：**若对or进行了过滤时，则相应的order,information中的or也被过滤了**

> ## 0x04 注释符（内联注释符）

在mysql中/*admin*/是注释符，就像C和js中//代表注释的意思，也可以充当空白符。因为 /**/在sql语句中可以解析成功。事实上许多WAF都考虑到/**/可以作为空白分，但是waf检测 “/*.**/”很消耗性能，工程师会折中，可能在检测中间引入一些特殊字符，例如：/*\w+*/。或者，WAF可能只中间检查n个字符“/*.{,n}*/”,直至达到检测的最大值，因此payload：

``` java 
index.php?id=-1 union/**/select 1,2,3
index.php?id=-1 union/*aaaaaaaaaaaaaaa(1万个a)aaaaaaaaaaaaaaaaa*/
```

还有用法为 /!50727select 1/，即当版本号小于等于50727时，执行select 1

> ## 0x05 垃圾字符

一般为了考虑性能等原因，程序员在设置WAF绕过规则时设置了过滤的数据包长度，如果数据包太大或太长，就会直接放弃匹配过滤后面的数据，从而略过这个数据包。因此我们可以通过传入大量的参数值，超到WAF绕过的临界值，从而绕过.

``` java
index.php?id=-1aaaaaa(10万个a)aaaa union select 1,2,3
```

> ## 0x06 参数污染

简单来说，存在多个同名参数的情况下，可能存在逻辑层和 WAF 层对参数的取值不同，即可能逻辑层使用的第一个参数，而 WAF 层使用的第二个参数，而这时我们只需要第二个参数正常，通过WAF层，然后在第一个参数中插入注入语句，这样组合起来就可以绕过 WAF，payload：

``` java
index.php?name=first&name=last
```

而由于部分中间件的不同，部分检测规则存在差异，下面是一些服务器检测规则：

![在这里插入图片描述](https://img-blog.csdnimg.cn/8b2d8e44a6d34ea9b7b6e19a1fc6ccb9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5LmwTGVtb27kuZ_nlKjlirU=,size_20,color_FFFFFF,t_70,g_se,x_16)

> ## 0x07 keep-alive(持久连接)

在HTTP请求头部中有Connection这个字段，用来判断建立的 TCP连接会根据此字段的值来判断是否断开，当发送的内容太大，超过一个 http 包容量，需要分多次发送时，值会变成keep-alive，Keep-Alive功能使客户端到服务器端的连接持续有效，当出现对服务器的后继请求时，Keep-Alive功能避免了建立或者重新建立连接。即本次发起的 http 请求所建立的 tcp 连接不断开，直到所发送内容结束Connection为close为止。
因此我们可以使用burpsuite抓包，手动将connection值设置为 keep-alive，然后在 http 请求报文中构造多个请求，将我们的注入代码隐藏在第 n 个请求中，从而绕过 waf。

> ## 0x08 请求方式绕过

一些 WAF 对于get请求和post请求的处理机制不一样，可能对 POST 请求稍加松懈，因此给GET请求变成POST请求有可能绕过拦截。
一些 WAF 检测到POST请求后，就不会对GET携带的参数进行过滤检测，因此导致被绕过。
一般方法便是采用burpsuite抓包，更改提交方式，如下:

![在这里插入图片描述](https://img-blog.csdnimg.cn/6bcc270dcc934c7984213eb916a17f18.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5LmwTGVtb27kuZ_nlKjlirU=,size_13,color_FFFFFF,t_70,g_se,x_16)

> ## 0x09 静态资源

特定的静态资源后缀请求，常见的静态文件(.js .jpg .swf .css等等)，类似白名单机制,waf为了提高检测效率，会直接放弃检测这样一些静态文件名后缀的请求。payload:

``` java 
index.php/1.js?id=1
```

备注: Aspx/php只识别到前面的.aspx/.php后面基本不识别

> ## 0x0A url白名单

为了防止误拦，部分WAF内置默认的白名单列表，如admin/manager/system等管理后台。只要url中存在白名单的字符串，就作为白名单不进行检测。常见的url构造姿势:
index.php/admin.php?id=1
index.php?a=/manage/&b=…/etc/passwd
index.php/…/…/…/ manage/…/sql.asp?id=2
WAF对传入的参数进行比较，只要uri中存在/manage/，/admin/ 就作为白名单直接放行，payload:

``` java 
index.php?a=/manage/&id=1 union select 1,2,3
```

> ## 0x0B 绕过空格

%20、%09、%0a、%0b、%0c、%0d、%a0、%00、/**/、 /*!select*/ 、()、–%0a（可以1-256都跑一遍）
其中%09需要php环境，%0a为\n， /!select/为mysql独有。常见用法为/!50727select 1/，即当版本号小于等于50727时，执行select 1

> ## 0x0C prepare预处理

一般形式：
set @a=0x73656c656374202a2066726f6d2074657374;
prepare s from @a;
execute s;

利用 char() 函数将select的ASCII码转换为select字符串，接着利用concat()函数进行拼接得到select查询语句，从而绕过过滤。或者直接用concat()函数拼接select来绕过。
char(115,101,108,101,99,116)<----->‘select’

``` java 
index.php?id=-1';SET @sqli=concat(char(115,101,108,101,99,116),'* from `1919810931114514`');PREPARE hacker from @sqli;EXECUTE hacker;#
```



以上便是我总结的一些SQL注入绕过的一些技巧和方法，可以根据需要采用最好的方法绕过。而对于WAF的更新与强大，手工注入具有一定的难度，一般我们采取人工+自写脚本+sqlmap工具配合使用的方法绕。