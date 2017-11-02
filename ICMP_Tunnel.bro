# Detect ICMP tunnel activity 

module ICMP_Tunnel;
export {
        redef enum Notice::Type += {
		ICMP_Tunnel,
        };
}
export {
    redef record SumStats::Key += {
    host2: addr &optional;
    };
}

function max(a: count,b: count):count
{
    if(a>b)
    return a;
    else
    return b;
}
function detect(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
if ( icmp$len <= 4)
  return;

local ml_packet ="2122232425262728292a2b2c2d2e2f3031323334353637";
local win_packet="6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869";
local win_packet1="4142434445464748494a4b4c4d4e4f5051525354555657414243444546474849";
local null_packet="000000000000000000000000";
local DC_ICMP_traffic="????????????????????????????????????????";
local cisco_IOS_ping="abcdabcdabcdabcdabcd";
local all_ones="FFFFFFFFFFFFFFFFFF";
local ones_zeros="AAAAAAAAAAAAAAAAAAA";
local DHCP_DuplicateIP_Check="4468637049636d7043686b";
local NOCTION_IRP="4e4f4354494f4e20495250";
local orig = icmp$orig_h;
local resp = icmp$resp_h;
local hex_string = bytestring_to_hexstr(payload[:icmp$len]);
local len=|hex_string|;
hex_string=hex_string[:len];
if(c$id$orig_h in private_address || c$id$resp_h in private_address || c$id$orig_h in whitelist_ip || c$id$resp_h in whitelist_ip)
    return;
    
if(all_ones !in hex_string && ones_zeros !in hex_string &&  cisco_IOS_ping !in hex_string && ml_packet[:max(icmp$len,46)] !in hex_string && win_packet[:icmp$len] !in hex_string && null_packet !in hex_string && win_packet1 !in hex_string && DHCP_DuplicateIP_Check !in hex_string && NOCTION_IRP !in 
hex_string)
{   
    SumStats::observe("ICMP Tunnel",
	                   SumStats::Key($host=c$id$orig_h,$host2=c$id$resp_h),
	                   SumStats::Observation($str=payload[:icmp$len]));

}
}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
   detect(c,icmp,id,seq,payload); 
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
   detect(c,icmp,id,seq,payload); 
}


event bro_init()
{
    const excessive_limit: double = 20  &redef;
    local icmp_reducer = SumStats::Reducer($stream="ICMP Tunnel", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name = "icmp",
	                  $epoch =15min ,
	                  $reducers = set(icmp_reducer),
	                  $threshold = excessive_limit,
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
		                {
		                return result["ICMP Tunnel"]$unique+0.0;
		                },
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		                {
		                NOTICE([$note=ICMP_Tunnel,
		                        $src=key$host,
					                  $dst=key$host2,
					                  $suppress_for=5min,
		                        $msg=fmt("ICMP tunnel detected between  %s and %s",key$host,key$host2)]);
		                }
	                ]);

}

hook Notice::policy(n: Notice::Info) &priority=5
	{
	if ( n$note == ICMP_Tunnel )
		n$actions = set(Notice::ACTION_ALERT);
	}
