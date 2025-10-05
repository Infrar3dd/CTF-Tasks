from Crypto.Util.number import long_to_bytes
import math

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def mulinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

def karatsuba_decrypt(ciphertext, n, d, e=65537):
    if isinstance(ciphertext, dict):
        c_high = ciphertext['c_high']
        c_low = ciphertext['c_low']
        c_sum = ciphertext['c_sum']
        split_point = ciphertext['split']

        high_m = pow(c_high, d, n)
        low_m = pow(c_low, d, n)
        sum_m = pow(c_sum, d, n)

        if (high_m + low_m) % n == sum_m:
            power = 10**split_point
            original_m = high_m * power + low_m
            return original_m
        else:

            for guess in range(1000): 
                test_high = (high_m + guess) % n
                test_low = (low_m - guess) % n
                if (test_high + test_low) % n == sum_m:
                    power = 10**split_point
                    original_m = test_high * power + test_low
                    return original_m

            power = 10**split_point
            original_m = high_m * power + low_m
            return original_m
            
    else:
        return pow(ciphertext, d, n)

def decrypt_message(ciphertext, n, d):
    try:
        if isinstance(ciphertext, dict):
            decrypted_long = karatsuba_decrypt(ciphertext, n, d)
            message = long_to_bytes(decrypted_long)
            return message.decode('utf-8', errors='ignore')
        else:
            decrypted_long = pow(ciphertext, d, n)
            message = long_to_bytes(decrypted_long)
            return message.decode('utf-8', errors='ignore')
            
    except Exception as e:
        print(f"Ошибка при расшифровке: {e}")
        return None

if __name__ == "__main__":
    
    n = 10861749151234514785409704377540524647518040357714783139945315616423223841299276432277200341245752658989600404334734918513603208360274239989202456022829193  # Замените на реальный модуль n
    d = 1653368471744442368421612384917592716841478410799436602287173178348689763657163129942462272777086145752970135163832465919962444003907128620723625997188993    # Замените на реальную приватную экспоненту d

    ciphertext = {
        'c_high': 7178480500234217770504682900254104365155035243686501915318063519962909509226117894587291761538966296607872210452074286559015694093246904489059538256183276,
        'c_low': 8991582191340142847675702775511015086393362134322859526386986597936005650340478585456014449095123348670544671610058359608880724107493040075995484243779434,
        'c_sum': 7574784192785484866960705911814503267970587170896438310928297263357981967130522378072628612055923862532562133095773163216361688510830276577118762774501947,
        'split': 47
    }
    
    decrypted = decrypt_message(ciphertext, n, d)
    if decrypted:
        print(f"Flag: {decrypted}")
    else:
        print("Smth went wrong")