# ZEEK 第一次笔记

## 作业任务

使用zeek脚本完成以下功能：

* 对于给定pcap数据，找出所有拥有三个以上用户代理(user-agent)的ip地址
* 输出"xxx.xxx.xxx.xxx is a proxy"

## ZEEK 脚本基础编写规则

### 事件导向

zeek脚本执行和一般C/Python等语言不同，并非是从某行代码开始循序执行(并加以函数封装)。zeek脚本由事件(event)触发，例如：

```
event zeek_init()
{
	print "HelloWorld!";
}
```

就是一个在整个zeek脚本激活的时候被触发，打印HelloWorld。因此，一般来说zeek脚本都在使用各种官方定义的event，并自定义在event被激活时要干什么。

### 变量的数据类型

zeek是静态语言，在声明变量时必须指定数据类型：

#### 基本数据类型

* bool：喜闻乐见的布尔值T和F，可以转换成count类型的1和0
* count：64位无符号整型
* int：64位有符号整型
* double：双精度浮点
* time：
* interval
* string：字符串
* pattern：正则表达式
* port：端口，格式形如 8080/tcp 或者 53/udp
* addr：ip地址，可以是ipv4或者ipv6地址，格式形如 192.168.1.100 或 [::ffff:192.168.1.100]
* subnet：子网号，格式形如 192.168.0.0/16 或 [fe80::]/64
* enum：

当我想要声明一个int类型的，变量名为xxx，值为-888的变量，语法如下：

```
# 可以在声明的同时赋值
xxx: int = -888;

# 或者先声明后赋值
xxx: int;
xxx = -888;

# 或者直接赋值，交给zeek解释器自行决定数据类型
# 一旦zeek解释器决定了数据类型，就不得再进行更改
# 不推荐
xxx = -888;
```

#### 高级数据结构

* table：类似python的字典，但是键和值的类型是静态的
* set：类似python的集合，集合项目类型也是静态的
* vector：类似C++STL的向量
* record：类似C++的结构体/类
* function：
* event：
* hook：
* file：
* opaque：
* any：

当我想声明一个{地址：域名}的字典(table)，名唤my_dns，语法如下：

```
# 方括号中是键的数据类型
# 之后是值的数据类型
my_dns: table[addr] of string;

# 向table中添加键值对{192.168.1.100: "home_net"}
my_dns[192.168.1.100] = "home_net";

# 也可以在生命的时候初始化
my_dns: table[addr] of string = {[192.168.1.100] = "home_net"};
```

当我想声明一个{协议名称}的集合(set)，名唤protocol_set，语法如下：

```
protocol_set: set[string];

# 向集合中添加元素
add protocol_set ["TCP"];

# 初始化
protocol_set: set[string] = {"TCP", "UDP"};
# 初始化(使用构造函数)
protocol_set = set("TCP", "UDP");

# |set|可以返回这个集合中元素的数量
print fmt("There are %d elements in this set.", |protocol_set|);
```

高级数据结构之间可以相互嵌套，例如我想要定义一个{地址：{UA集合}}字典，语法如下：

```
ip_ua_table: table[addr] of set[string];

# 添加元素 192.168.1.102: "Android"
if (192.168.1.102 in ip_ua_table)
{
	add ip_ua_table[192.168.1.102] ["Android"];
}
else
{
	ip_ua_table[192.168.1.102] = set("Android");
}
```

### 变量作用域

zeek的变量拥有两种作用域：

* global：全局变量，可以由多个event共享
* local：局部变量，在event内部使用

所有变量必须在声明时确定作用域：

```
global xxx: set[addr];

event zeek_init()
{
	local yyy: addr = 192.168.1.100;
	if (yyy in xxx)
	{
		print fmt("Hello %s!", yyy);
	}
	else
	{
		add xxx [yyy];
		print fmt("%s is added to xxx!", yyy);
	}
}
```

## EVENT 使用方法

除了不带参数的基本事件，例如zeek_init()和zeek_done()，大多数事件都是带有参数的。这个参数并非是需要用户输入的，而是触发事件之后zeek从pcap数据之中解析出来的，相当于已经帮你写好了，例如：

```
event http_header(c: connection, is_orig: bool, name: string, value:string)
```

这个event在检测到http报文头部式触发，共有四个参数：

* c：一个connection类(record)对象，connection结构体中包含了很多属性(部分属性自身也是类的对象)。在使用类对象的属性时，并使和C/Python类似的使用"."来连接(因为在IP地址中已经使用过"."了)，而是使用"\$"表示相同的含义。同时"?\$"表示"类对象是否含有后面的属性"，返回一个布尔值作为判断结果。
* is_orig：一个布尔类型的flag，代表这条报文是否来自连接的发起方。在zeek中报文不分成"源地址src"->"宿地址dst"，而是按照"发起者orig"<->"回复者rply"定义的，更方便在不同情况下确定通信的双方身份
* name：一个字符串(干啥的：pass)
* value：包含了整个报头信息的字符串

## 作业解答

```
global ip_ua_table: table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value:string)
{
	if (c?$http && c$http?$user_agent)
	{
		local orig_ip_addr: addr = c$id$orig_h;
		local ua: string = c$http$user_agent;
		if (orig_ip_addr in ip_ua_table)
		{
			add ip_ua_table[orig_ip_addr] [ua];
		}
		else
		{
			ip_ua_table[orig_ip_addr] = set(ua);
		}
	}
}


event zeek_done()
{
	for (orig_ip_addr in ip_ua_table)
	{
		if (|ip_ua_table[orig_ip_addr]| >= 3)
		{
			print fmt("%s is a proxy", orig_ip_addr);
		}
	}
}
```

