import numpy as np
import sys
from readpw import Passwords

def compute_black_list_succ(fname, b, q, sketch_size):
    """Computes the offline success rate of an attacker who has access to
    the sketch and wants to make q (int) queries per password.  

    b is either a number or a set. If b is a number then this specify
    black listing top b passwords.  fname is the attacker's password
    model. In case b is a number, then the black list is chosen from
    the top b passwords of the attacker's model, which sounds iffy,
    but that implies that the attacker has complete knowledge of the
    real password distribuion. 
    """
    pwf = Passwords(fname)
    n_sketches = 2**sketch_size
    n = q * n_sketches
    pwarr, farr = ['' for _ in range(n)], [0 for _ in range(n)]
    pwiter = pwf.iterpws()
    for i in range(n):
        pwarr[i], farr[i] = pwiter.next()
    if isinstance(b, int):
        b = pwarr[:b]
    if not isinstance(b, set):
        b = set(b)
    i, j = 0, 0
    nfarr = np.zeros(n * n_sketches)
    for i in range(n):
        if pwarr[i] in b:
            nfarr[j:j+n_sketches] = float(farr[i])/n_sketches
            j += n_sketches
        else:
            nfarr[j] = farr[i]
            j += 1
        if j>nfarr.shape[0]: break
    print nfarr.shape, n
    if nfarr.shape[0]<n:
        return  -np.partition(-nfarr, n)[:n].sum()/pwf.totalf()
    else:
        return nfarr.sum()/pwf.totalf()


def entropy(rpw):
    pass

def policy(rpw, tpw):
    pass

def create_typo_balls(fname):
    pass

def compute_online_guessing(fname, q):
    pass

if __name__ == "__main__":
    print compute_black_list_succ(sys.argv[1], 0, 1000, 0)
