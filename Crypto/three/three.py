c1 = 92262024248981860103280873542252256628134976821691837120749369308438126936475512475970097604122605777834204420314937898925653830508674806612411329698050410536897382517201052539904948051593190605802862483900
c2 = 40137974563338794074595395088571641226410589555421291059139107847448738576507377880865521300913166500779906866058153101295273536522711754723374642716610556570127593336877351624409753636971878806032253678633271
c3 = 912333382684347226677078458560223293632390839952039642855445123492250584464960089013383192462798723606256744047093117433863508527411319945004792514382362748295257570329274794194275851778681650146341095871825314

N1 = 770208589881542620069464504676753940863383387375206105769618980879024439269509554947844785478530186900134626128158103023729084548188699148790609927825292033592633940440572111772824335381678715673885064259498347
N2 = 106029085775257663206752546375038215862082305275547745288123714455124823687650121623933685907396184977471397594827179834728616028018749658416501123200018793097004318016219287128691152925005220998650615458757301
N3 = 982308372262755389818559610780064346354778261071556063666893379698883592369924570665565343844555904810263378627630061263713965527697379617881447335759744375543004650980257156437858044538492769168139674955430611

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Reverse element doesnt exist")
    return x % m

def chinese_remainder_theorem(congruences):
    M = 1
    for _, m in congruences:
        M *= m
    result = 0
    for a, m in congruences:
        Mi = M // m
        try:
            Mi_inv = mod_inverse(Mi, m)
            result = (result + a * Mi * Mi_inv) % M
        except:
            return None
    return result

def integer_root(n, k):
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    x = 1
    while x ** k <= n:
        x *= 2
    low = x // 2
    high = x
    while low <= high:
        mid = (low + high) // 2
        power = mid ** k
        if power == n:
            return mid, True
        elif power < n:
            low = mid + 1
        else:
            high = mid - 1
    return high, False

def bytes_to_text(bytes_data):
    try:
        return bytes_data.decode('utf-8')
    except:
        try:
            return bytes_data.decode('latin-1')
        except:
            return None

def try_decode_number(n):
    hex_str = hex(n)[2:]
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str
    try:
        bytes_data = bytes.fromhex(hex_str)
        text = bytes_to_text(bytes_data)
        if text and all(32 <= ord(c) <= 126 for c in text[:50] if text):
            return text
    except:
        pass
    return None

for e in [3, 5, 7, 17, 65537]:
    for i, (c, n) in enumerate([(c1, N1), (c2, N2), (c3, N3)], 1):
        root, exact = integer_root(c, e)
        if exact and root < n:
            text = try_decode_number(root)
            if text:
                print(text)
                exit()

if gcd(N1, N2) == 1 and gcd(N1, N3) == 1 and gcd(N2, N3) == 1:
    for e in [3, 5, 7]:
        congruences = [(c1, N1), (c2, N2), (c3, N3)]
        result = chinese_remainder_theorem(congruences)
        if result is not None:
            root, exact = integer_root(result, e)
            if exact:
                text = try_decode_number(root)
                if text:
                    print(text)
                    exit()