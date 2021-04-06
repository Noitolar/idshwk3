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
