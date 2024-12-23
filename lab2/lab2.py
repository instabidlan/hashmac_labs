import random
import Crypto.Hash.RIPEMD160 as ripemd160
import concurrent.futures
import pickle
from colorama import Fore, Back, Style

from typing import Optional

HASH_OUTPUT_SIZE = 16


def theor_calc(K: int, L: int, N: int, t: int):
    def _th_calc(K: int, L: int, N: int):
        s = 0
        for i in range(1, K+1):
            for j in range(L-1):
                if (i * L)/N >= 1:
                    continue
                s += pow((1 - (i * L)/N), j + 1)
        return (1/N)*s
    return 1 - pow((1 - _th_calc(K, L, N)), t) if t > 1 else _th_calc(K, L, N)


def ret_hash(msg: bytes, _trunc: Optional[int] = None) -> bytes:
    if _trunc:
        return ripemd160.new(msg).digest()[:_trunc // 8]
    return ripemd160.new(msg).digest()


def R(r: bytes, x: bytes) -> bytes:
    return r + x


def build_table(K: int, L: int) -> tuple[bytes, list[tuple]]:
    r = random.getrandbits(128 - HASH_OUTPUT_SIZE).to_bytes((128 - HASH_OUTPUT_SIZE) // 8, "big")
    table = []

    for i in range(K):
        xi0 = random.getrandbits(HASH_OUTPUT_SIZE).to_bytes(HASH_OUTPUT_SIZE // 8, "big")
        xiL = xi0
        for j in range(L): 
            xiL = ret_hash(R(r, xiL), HASH_OUTPUT_SIZE)

        table.append((xi0, xiL))

    return r, sorted(table, key=lambda x: x[1])


def _find_preimage(L: int, table: tuple[bytes, list[tuple]], target: str) -> Optional[bytes]:
    c = 0
    y = target
    r, tab = table
    for j in range(L):
        low, high = 0, len(tab) - 1
        while low <= high:
            mid = (low + high) // 2
            if tab[mid][1] < y:
                low = mid + 1
            elif tab[mid][1] > y:
                high = mid - 1
            else:
                xi0, _ = tab[mid]
            
                x = xi0
                for m in range(L - j):
                    if ret_hash(R(r, x), HASH_OUTPUT_SIZE) == y:
                        return c, R(r, x)
                    x = ret_hash(R(r, x), HASH_OUTPUT_SIZE)
                return c, None

            c += 1
        y = ret_hash(R(r, y), HASH_OUTPUT_SIZE)
    
    return c, None


def find_preimages_parallel(L: int, tables: list[tuple[bytes, list[tuple]]], target: str) -> tuple[int, Optional[bytes]]:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(_find_preimage, L, table, target): table for table in tables}
        
        for future in concurrent.futures.as_completed(futures):
            c, result = future.result()
            if result is not None:
                return c, result  
            
    return c, None


def attack_multithread(K: int, L: int, t: int = 1, mode: int = 1, suppress: bool = True, num_threads: int = 4) -> None:
    N = 10000
    success = 0
    primg = None

    last_preimage = None
    last_rand_vec = None
    last_c = None

    print(f"{Fore.CYAN}[i]{Fore.RESET} K: {K}, L: {L}, table_count: {t}")
    print(f"{Fore.CYAN}[i]{Fore.RESET} Theoretical success probability per attack: {theor_calc(K, L, N, t) * 100:.2f}%\n")
    if mode == 1:
        # precompute tables
        print(f"{Fore.CYAN}[i]{Fore.RESET} Precomputing tables...")
        tables = []
        for _ in range(t):
            tables.append(build_table(K, L))

        # save precomputed tables
        with open(f'rainbow_table_{K}_{L}_{t}.pkl', 'wb') as f:
            pickle.dump((K, L, t, tables), f)

        print(f"{Fore.CYAN}[i]{Fore.RESET} Tables built\n")

    elif mode == 2:
        # load precomputed tables
        with open(f'rainbow_table_{K}_{L}_{t}.pkl', 'rb') as f:
            _K, _L, _t, tables = pickle.load(f)
            assert K == _K and L == _L and t == _t, f"{Fore.WHITE}{Back.RED}[e]{Fore.RESET}{Back.RESET} Invalid table dimensions"

        print(f"{Fore.CYAN}[i]{Fore.RESET} Use precomputed tables\n")

    def attack_iteration(j):
        if j % 100 == 0:
            print(f"{Fore.CYAN}[i]{Fore.RESET} Iteration: {j + 1}", end="\r")
        nonlocal success, primg, last_preimage, last_rand_vec, last_c
        rand_vec = random.getrandbits(256).to_bytes(32, "big")
        target = ret_hash(rand_vec, HASH_OUTPUT_SIZE)
        if not suppress:
            print(f"{Style.BRIGHT}{Fore.CYAN}[i]{Fore.RESET} Random vector: {rand_vec}")
            print(f"{Fore.CYAN}[i]{Fore.RESET} Target: {target}")
        c, preimg = find_preimages_parallel(L, tables, target)
        if ret_hash(preimg, HASH_OUTPUT_SIZE) == target:
            success += 1
            primg = preimg
            last_preimage = primg
            last_rand_vec = rand_vec
            last_c = c
            if not suppress:
                print(f"{Fore.GREEN}[*]{Fore.RESET} {Back.GREEN}Preimage: {primg}{Back.RESET}\n{Fore.GREEN}[*]{Fore.RESET} {Back.GREEN}Hash: {ret_hash(primg, HASH_OUTPUT_SIZE)}{Back.RESET}\n{Fore.GREEN}[*]{Fore.RESET} Iterations: {c}\n{Fore.GREEN}[*]{Fore.RESET} Successes: {success}{Style.RESET_ALL}\n")
        else:
            if not suppress:
                print(f"{Style.BRIGHT}{Fore.RED}[*]{Fore.RESET} No preimage found{Style.RESET_ALL}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        list(executor.map(attack_iteration, range(N)))

    print(f"{Fore.GREEN}[*]{Fore.RESET} Last random vector: {last_rand_vec}\n{Fore.GREEN}[*]{Fore.RESET} Last preimage: {last_preimage}\n{Fore.GREEN}[*]{Fore.RESET} Last target hash: {ret_hash(last_rand_vec, HASH_OUTPUT_SIZE)}\n{Fore.GREEN}[*]{Fore.RESET} Last preimage hash: {ret_hash(last_preimage, HASH_OUTPUT_SIZE)}\n{Fore.GREEN}[*]{Fore.RESET} Last succesfull attack iter count: {last_c}\n{Fore.GREEN}[*]{Fore.RESET} Successes: {success}\n{Fore.GREEN}[*]{Fore.RESET} Success rate: {success / N * 100:.2f}%\n")


if __name__ == "__main__":
    K = [2**10, 2**12, 2**14]
    L = [2**5, 2**6, 2**7]
    t = [1, 16]
    N = 2**HASH_OUTPUT_SIZE

    for _t in t:
        for k in K:
            for l in L:
                # mode 1: precompute tables; mode 2: use precomputed tables
                attack_multithread(k, l, _t, mode=1, num_threads=32)

    