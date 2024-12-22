import Crypto.Hash.RIPEMD160 as ripemd160
import colorama as col
import numpy as np
import math
from typing import Optional
from os import urandom
import csv


PREIMAGE_ATTACK_CONSTRAINT = 16
# PREIMAGE_ATTACK_CONSTRAINT = 8
# COLL_ATTACK_CONSTRAINT = 16
COLL_ATTACK_CONSTRAINT = 32


def ret_hash(msg: bytes, _trunc: Optional[int] = None) -> str:
    if _trunc:
        return ripemd160.new(msg).hexdigest()[:_trunc // 4]
    return ripemd160.new(msg).hexdigest()


def colorize_ret_hash(msg: bytes, _trunc: int) -> str:
    h = ret_hash(msg)
    return col.Fore.RED + h[:_trunc // 4] + col.Fore.RESET + h[_trunc // 4 + 1:]


def _first_v(msg: bytes) -> bytes:
    bytes_c = 1 + int.from_bytes(urandom(1)) % 32
    return msg + str(int.from_bytes(urandom(bytes_c))).encode("ascii")


def _second_v(msg: bytes) -> bytes:
    return msg[:(ind := ord(urandom(1)) % len(msg))] + urandom(1) + msg[ind + 1:]


def ret_modification(var: int = 0, *args, **kwargs):
    return {
        0: _first_v,
        1: _second_v
    }[var](*args, **kwargs)


def preimage_attack(msg: bytes, var: int = 0, supress: bool = False) -> tuple[int, bytes]:
    target_hash = ret_hash(msg, PREIMAGE_ATTACK_CONSTRAINT)
    iter_count = 0
    m = msg
    h = ret_hash((m := ret_modification(var, msg=m)), PREIMAGE_ATTACK_CONSTRAINT)
    used_candidates = {m}

    while True:
        if not supress:
            if iter_count < 30:
                print(f"{str(iter_count + 1)}. Potential preimage:\n{repr(m)[2:-1]}\nHash:\n\t{colorize_ret_hash(m, PREIMAGE_ATTACK_CONSTRAINT)}\n\t{colorize_ret_hash(msg, PREIMAGE_ATTACK_CONSTRAINT)}")
            else:
                if iter_count == 30:
                    print("\nWaiting...")

        if m != msg and h == target_hash:
            break

        if var == 0:
            m = msg

        while m in used_candidates:
            m = ret_modification(var, msg=m)

        h = ret_hash(m, PREIMAGE_ATTACK_CONSTRAINT)
        used_candidates.add(m)

        iter_count += 1
    
    if not supress:
        print(f"\n\n\n{col.Back.LIGHTGREEN_EX}{col.Fore.BLACK}Found preimage:{col.Back.RESET}{col.Fore.RESET}\n{repr(m)[2:-1]}\nHash:\n\t{colorize_ret_hash(m, PREIMAGE_ATTACK_CONSTRAINT)}\n\t{colorize_ret_hash(msg, PREIMAGE_ATTACK_CONSTRAINT)}")
    return iter_count, m


def coll_attack(msg: bytes, var: int = 0, supress: bool = False) -> tuple[int, bytes, bytes]:
    iter_count = 0
    
    init_m = msg
    m = msg
    h = ret_hash(m := ret_modification(var, msg=m), COLL_ATTACK_CONSTRAINT)
    hashes = dict()

    while True:
        hashes[h] = m
        if not supress:
            if iter_count < 30:
                print(f"\n{col.Back.CYAN}{str(iter_count + 1)}. Potential Collision Candidate:{col.Back.RESET}\n{repr(m)[2:-1]}\nHash:\n\t{colorize_ret_hash(m, COLL_ATTACK_CONSTRAINT)}")
            else:
                if iter_count == 30:
                    print("\nWaiting...")
            # print(f"\n{col.Back.CYAN}{str(iter_count + 1)}. Potential Collision Candidate:{col.Back.RESET}\n{repr(m)[2:-1]}\nHash:\n\t{colorize_ret_hash(m, COLL_ATTACK_CONSTRAINT)}")

        if var == 0:
            m = init_m

        while m in hashes.values():
            m = ret_modification(var, msg=m)

        h = ret_hash(m, COLL_ATTACK_CONSTRAINT)

        iter_count += 1
        if h in hashes.keys() and hashes[h] != m:
            m1 = hashes[h]
            m2 = m
            break

    if not supress:
        print(f"\n\n\n{col.Back.LIGHTGREEN_EX}{col.Fore.BLACK}Found collision:{col.Back.RESET}{col.Fore.RESET}\n{repr(m1)[2:-1]}\n{repr(m2)[2:-1]}\nHashes:\n\t{colorize_ret_hash(m1, COLL_ATTACK_CONSTRAINT)}\n\t{colorize_ret_hash(m2, COLL_ATTACK_CONSTRAINT)}")

    return iter_count, m1, m2


def calculate_mean(data):
    return np.mean(data)


def calculate_variance(data):
    return np.var(data, ddof=1)


def calculate_confidence_interval(mean, variance, n):
    std_dev = math.sqrt(variance)
    t_value = 1.95 
    margin_of_error = t_value * (std_dev / math.sqrt(n))
    return (float(mean - margin_of_error), float(mean + margin_of_error))


def main_collision(var: int = 0):
    data = []
    message = b"Tsema Vladyslav Vitaliyovich" + urandom(32)
    print(f"Init message: {repr(message)[2:-1]}\nTarget hash: {colorize_ret_hash(message, COLL_ATTACK_CONSTRAINT)}\n\n")
    iter_count, m1, m2 = coll_attack(message, var)
    data.append(iter_count)

    for i in range(99):
        print(f"{i + 1}/100 ...", end='\r')
        message = b"Tsema Vladyslav Vitaliyovich" + urandom(32)
        iter_count, m1, m2 = coll_attack(message, var, True)
        print(f"{i + 1}. Collision: (...{str(m1[48:])}, ...{str(m2[48:])}); Iterations: {iter_count}\n")
        data.append(iter_count)


    m = calculate_mean(data)
    v = calculate_variance(data)
    print(f"Mean: {m}")
    print(f"Variance: {v}")
    print(f"Confidence interval: {calculate_confidence_interval(m, v, 100)}")

    with open(f'data_coll_var_{var}.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Iteration", "Count"])
        for i, value in enumerate(data):
            writer.writerow([i + 1, value])


def main_preimg(var: int = 0):
    data = []
    message = b"Tsema Vladyslav Vitaliyovich" + urandom(32)
    print(f"Init message: {repr(message)[2:-1]}\nTarget hash: {colorize_ret_hash(message, PREIMAGE_ATTACK_CONSTRAINT)}\n\n")
    iter_count, _m = preimage_attack(message, var)
    data.append(iter_count)

    for i in range(99):
        print(f"{i + 1}/100 ...", end='\r')
        message = b"Tsema Vladyslav Vitaliyovich" + urandom(32)
        iter_count, _m = preimage_attack(message, var, True)
        print(f"{i + 1}. Preimage: {_m[48:]}; Iterations: {iter_count}\n")
        data.append(iter_count)
        

    m = calculate_mean(data)
    v = calculate_variance(data)
    print(f"Mean: {m}")
    print(f"Variance: {v}")
    print(f"Confidence interval: {calculate_confidence_interval(m, v, 100)}")

    with open(f'data_preim_var_{var}.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Iteration", "Count"])
        for i, value in enumerate(data):
            writer.writerow([i + 1, value])


if __name__ == "__main__":
    print(f"{col.Back.RED}Collision attack (attack var 1):{col.Back.RESET}")
    main_collision(0)
    print(f"\n{col.Back.RED}Collision attack (attack var 2):{col.Back.RESET}")
    main_collision(1)

    print(f"\n\n{col.Back.RED}Preimage attack (attack var 1):{col.Back.RESET}")
    main_preimg(0)
    print(f"\n{col.Back.RED}Preimage attack (attack var 2):{col.Back.RESET}")
    main_preimg(1)
