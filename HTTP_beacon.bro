module HTTP_beacon;

global time_vec: table[addr,string] of vector of time;

export {
        redef enum Notice::Type += {
        HTTP_beacon,
        };
}

function stdev(s :vector of count): double
{
    local len=|s|;
    if (len<2)
    {
      return 2;
    }
    local sum=0.0;
    local var=0.0;
    local new_sum=0.0;
    for(i in s)
    {
        sum=sum+s[i];
    }
    local mean=sum/len;
    local limit=mean*2/3;
    for(i in s)
    {
      if(|s[i]-mean| > limit)
          s[i]=double_to_count(mean); 
      new_sum=new_sum+s[i];
    }
    local new_mean=new_sum/len;
    for(i in s)
    {   
    #remove stray values
        var=var+(s[i]-new_mean)*(s[i]-new_mean); 
    }
    var=var/len-1;
    return sqrt(var);
}

function diff(v :vector of time): count
{
    local ts:vector of count;
    local len:vector of count;
    local i=0;local j=0;local k=0;
    
    #calculate the time difference between consecutive packets
    while(i<|v|-1)
    {
        ts[j]=double_to_count(interval_to_double(v[i+1]-v[i]));
        i=i+1;
        j=j+1;
    }
    
    #check for beacons
    if( |ts|>5 && stdev(ts) < 1.0 )
        return 1;
    
    #check to clean old data
    if(|ts| > 50 || (current_time()-v[0]>=72 hr && |ts|<10))
        return 0;
   return 2;
}

event scheduler()
{
    local host: addr;
    local domain: string;
    local str="";
        for ([host,domain] in time_vec)
        {   
        if(|time_vec[host,domain]| > 5)  
        {   
        local res=diff(time_vec[host,domain]);
        if(res==1)
        {
                NOTICE([$note=HTTP_beacon,
                $src=host,          
                $msg=fmt("HTTP beacon detected from  %s to %s",host,domain)]);
        }       
        else if (res==0)
        {
        delete time_vec[host,domain];
        }
        }
        }
        schedule 15 sec { scheduler() };
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{ 
    if (c$http?$method && c$http?$host && is_orig)
    {
           if([c$id$orig_h,c$http$host] !in time_vec)
               time_vec[c$id$orig_h,c$http$host] = vector(c$http$ts);
            else
                time_vec[c$id$orig_h,c$http$host][|time_vec[c$id$orig_h,c$http$host]|]=c$http$ts;      
    }

}

event bro_done()
{
    event  scheduler() ;
}
