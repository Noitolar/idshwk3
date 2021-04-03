global UaTable: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value:string)
{
	if (c?$http && c$http?$user_agent)
	{
		local source_ip_addr: addr = c$id$orig_h;
		local ua: string = c$http$user_agent;
		if (source_ip_addr in UaTable)
		{
			add UaTable[source_ip_addr][ua];
		}
		else
		{
			UaTable[source_ip_addr] = set(ua);
		}
	}
}


event zeek_done()
{
	for (ip_addr in UaTable)
	{
		if (|UaTable[ip_addr]| >= 3)
		{
			print fmt("%s is a proxy", ip_addr);
		}
	}
	
}
