def generate_internal_targets():
    # أشهر البورتات اللي بيستخدمها المبرمجين للخدمات الداخلية
    common_ports = [80, 443, 3000, 5000, 8000, 8080, 8443, 9000]
    # أشهر الـ IPs الداخلية (Localhost والـ Docker gateway)
    internal_ips = ["127.0.0.1", "localhost", "172.17.0.1"]
    
    targets = []
    for ip in internal_ips:
        for port in common_ports:
            targets.append(f"http://{ip}:{port}/admin")
            targets.append(f"http://{ip}:{port}/config")
    
    return targets
