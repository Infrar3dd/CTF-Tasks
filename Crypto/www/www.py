from Crypto.Util.number import long_to_bytes, GCD
import math

def wiener_attack(e, n):
    def continued_fractions(n, d):
        cf = []
        while d:
            q, r = divmod(n, d)
            cf.append(q)
            n, d = d, r
        return cf

    def convergents(cf):
        num, den = [], []
        for i in range(len(cf)):
            if i == 0:
                num.append(cf[0])
                den.append(1)
            elif i == 1:
                num.append(cf[0]*cf[1] + 1)
                den.append(cf[1])
            else:
                num.append(cf[i]*num[i-1] + num[i-2])
                den.append(cf[i]*den[i-1] + den[i-2])
            yield (num[i], den[i])
    
    cf = continued_fractions(e, n)
    convergents_list = list(convergents(cf))
    
    for k, d in convergents_list:
        if k == 0:
            continue

        phi = (e * d - 1) // k

        b = n - phi + 1
        discriminant = b * b - 4 * n
        
        if discriminant >= 0:
            root = math.isqrt(discriminant)
            if root * root == discriminant:
                p = (b + root) // 2
                q = (b - root) // 2
                if p * q == n:
                    return d, p, q
    return None, None, None

def common_factor_attack(n, e, c):
    print("Trying Wiener attack...")
    d, p, q = wiener_attack(e, n)
    
    if d is not None:
        print("Success via Wiener attack!")
        print(f"d = {d}")
        print(f"p = {p}")
        print(f"q = {q}")

        m = pow(c, d, n)
        return long_to_bytes(m).decode('utf-8', errors='ignore')
    
    print("Checking for common divisors...")
    
    for i in range(2, 100000):
        if n % i == 0:
            p = i
            q = n // i
            print(f"Found prime divisor: {p}")
            
            phi = (p - 1) * (q - 1)
            g = GCD(e, phi)
            
            if g == 1:
                d = pow(e, -1, phi)
                m = pow(c, d, n)
                return long_to_bytes(m).decode('utf-8', errors='ignore')
            else:
                print(f"e and φ(n) have common divisor: {g}")
                e_reduced = e // g
                if GCD(e_reduced, phi) == 1:
                    d = pow(e_reduced, -1, phi)
                    m = pow(c, d, n)
                    for i in range(g + 1):
                        try:
                            flag = long_to_bytes(m + i * phi).decode('utf-8', errors='ignore')
                            if 'donguCTF' in flag or 'CTF' in flag:
                                return flag
                        except:
                            pass
    
    print("Checking factordb.com...")
    try:
        import requests
        url = f"http://factordb.com/api?query={n}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"Factordb status: {data['status']}")
            if data['status'] == 'FF':
                factors = data['factors']
                if len(factors) == 2:
                    p = int(factors[0][0])
                    q = int(factors[1][0])
                    phi = (p - 1) * (q - 1)
                    d = pow(e, -1, phi)
                    m = pow(c, d, n)
                    return long_to_bytes(m).decode('utf-8', errors='ignore')
    except:
        pass
    
    return None

n = 100320068364485718188427819815797023704866688235829095689907404221230968223681726490759177060938864347095149062673469862096395547146020955851530302640593750403838432356394752397568353477104556092630239052347212188916151069905826607051987205795370954737933233874350976191818951095816724420066227013418688414779
e = 65578269701926524094618820551169797129483545074342334789550103751684874525682211643195583335252894591117039110383797796629442293967973278832947151070094825152873558079655569427290224148313059757346664821466972035834422876469691283702263351444847257692037178714089138538194027633721265360887041048769401730221
c = 79820614375401382021885268466133372451475509731949813427755341981893849688202254405781405783079821900337018380919804872927772388001726463719703495617720751737357931047540660513463944257240845167519119644044371785491008790071163883388371628136635426925913620667760612246314938085539037403705161512839285787123

result = common_factor_attack(n, e, c)

if result:
    print(f"\nDecrypted flag: {result}")
else:
    print("\nFailed to decrypt automatically")
    print("\nAdditional ideas:")
    print("1. Check manually on factordb.com")
    print("2. e is very large - possibly d is small")
    print("3. Possibly e and φ(n) are not coprime")