#!/usr/bin/env python3
from __future__ import print_function
import sys, os
import bz2, re
import itertools
import operator
import marisa_trie
import numpy as np
from os.path import (expanduser)
from math import sqrt
# opens file checking whether it is bz2 compressed or not.
import tarfile

"""A simple password library. Has function to put passwords into nice data
structure for fast look up.

The file creates a cache databse file in home folder with the name .passwords.

In Unix you can find it using `~/.pypasswords`. 

Run with Python 3 your life will be much easier.  """

MAX_INT = 2**64-1
DEBUG = True


home = expanduser("~")
pass_dir = os.path.join(home, '.pypasswords')
ROCKYOU_TOTAL_CNT = 32603388.0

def sample_following_dist(handle_iter, n, totalf):
    """Samples n passwords following the distribution from the handle
    @handle_iter is an iterator that gives (pw,f) @n is the total
    number of samle asked for @totalf is the total number of users,
    which is euqal to sum(f for pw,f in handle_iter)
    As, handle_iterator is an iterator and can only traverse once, @totalf
    needs to be supplied to the funciton.

    Returns, an array of @n tuples (id, pw) sampled from @handle_iter.
    """
    multiplier = 1.0
    if totalf == 1.0:
        multiplier = 1e8
        # print "WARNING!! I don't except probabilities"

    totalf = totalf * multiplier
    print("# Population Size", totalf)
    A = np.sort(np.unique(np.random.randint(0, totalf, size=n*2))[:n])
    A = A[::-1]
    # Uniqueness check, non necessarily required, but not very
    # computationally intensive
    assert len(A) == n, "Not enough randomnumbers generated"\
        "Requried {}, generated only {}".format(n, len(A))
    j = 0
    sampled = 0
    val = A.pop()
    # print handle_iter
    for _,w,f in handle_iter:
        j += f*multiplier
        if not A: break
        while val<j:
            sampled += 1
            if sampled %5000 == 0:
                print ("Sampled:",sampled)
            yield (val, w)
            if A:
                val = A.pop()
            else:
                break

    print ("# Stopped at:", w, f, j, '\n')
    while A and val<j:
        yield (val, w)
        if A:
            i, val = A.pop()
        else:
            break

def MILLION(n):
    return n*10e6

def sort_dict(D):
    # sort the dictionary by keys and returns a tuple list
    return sorted(D.items(), key=operator.itemgetter(1))

# returns the type of file.
def file_type(filename):
    magic_dict = {
        b"\x1f\x8b\x08": "gz",
        b"\x42\x5a\x68": "bz2",
        b"\x50\x4b\x03\x04": "zip"
    }
    max_len = max(len(x) for x in magic_dict)
    with open(filename, 'rb') as f:
        file_start = f.read(max_len)
    for magic, filetype in magic_dict.items():
        if file_start.startswith(magic):
            return filetype
    return "no match"


def open_(filename, mode='r'):
    """Replace with tarfile.open in future, and ignore Python2"""
    if mode == 'w':
        type_ = filename.split('.')[-1]
    else:
        type_ = file_type(filename)
    if type_ == "bz2":
        f = bz2.open(filename, mode + 't', errors='replace')
    elif type_ == "gz":
        f = tarfile.open(filename, mode)
    else:
        f = open(filename, mode)
    return f


def getallgroups(arr, k=-1):
    """
    returns all the subset of @arr of size less than equalto @k
    the return array will be of size sum_{i=1}^k nCi, n = len(arr)
    """
    if k<0:
        k = len(arr)
    return itertools.chain.from_iterable(
        itertools.combinations(set(arr), j)
        for j in range(1,k+1)
    )


def is_asciistring(s):
    try:
        s.decode('ascii')
        return True
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        # warning("UnicodeError:", s, str(e))
        return False

def get_line(file_object, limit=-1, pw_filter=lambda x: True):
    regex = re.compile(r'\s*([0-9]+) (.*)$')
    i = 0
    for l in file_object:
        if limit>0 and limit<=i:
            break
        m = regex.match(l)
        if not m:
            warning ("REGEX FAIL: ", l)
        c, w = m.groups()
        c = int(c)
        w = w.replace('\x00', '\\x00')
        # try:
        #     w = w.decode('utf-8', errors='replace')
        # except UnicodeDecodeError:
        #     #try with latin1
        #     warning("Error in decoding: ({} {}). Line: {}. Ignoring!"\
        #             .format(w, c, l))
        #     continue
        if w and pw_filter(w) and c>0:
            i += 1
            yield w,c
        else:
            pass
            #warning ("Filter Failed or malformed string: ", w, c)


def open_get_line(filename, limit=-1, **kwargs):
    """Opens the password file named @filename and reads first @limit
    passwords. @kwargs are passed to get_line for further processing.
    For example, pw_filter etc.
    @fielname: string
    @limit: integer
    """
    with open_(filename) as f:
        for w,c in get_line(f, limit, **kwargs):
            yield w, c

regex = r'([A-Za-z_]+)|([0-9]+)|(\W+)'
def print_err( *args ):
    if DEBUG:
        sys.stderr.write(' '.join([str(a) for a in args])+'\n')

def tokens(w):
    T = []
    while w:
        m = re.match(regex, w)
        T.append(m.group(0))
        w = w[len(T[-1]):]
    return T


def whatchar(c):
    return 'L' if c.isalpha() else \
        'D' if c.isdigit else 'Y'

def mean_sd(arr):
    s = sum(arr)
    s2 = sum([x * x for x in arr])
    n = len(arr)
    m = s / float(n)
    sd = sqrt(float(s2) / n - m * m)
    return m, sd


def convert2group(t, totalC):
    """
    What is this?
    """
    return t + np.random.randint(0, (MAX_INT-t)/totalC) * totalC

def warning(*objs):
    if DEBUG:
        print("WARNING: ", *objs, file=sys.stderr)

# assumes last element in the array(A) is the sum of all elements
def getIndex(p, A):
    p %= A[-1]
    i = 0
    for i, v in enumerate(A):
        p -= v
        if p < 0: break
    return i

class Passwords(object):
    """Its a class to efficiently store and read large password file. It
    creates two files for each password in the under the directory
    'eff_data/' in home+.pypassword directory (~/.pypasswords). First file
    is a trie, which just stores all the password in efficient prefix
    trie format using "marisa_trie" module. The second is a numy large
    array, containing the indicies. This is what I found the most
    memory and compute efficient way of accessing passwords in Python.
    @pass_file: the path of the file you want to process. The file
    should countain freq and the password similar to the output of
    unix "uniq -c" command.
    @max_pass_len, min_pass_len defines the
    range of password to consider. Note, this filtering does not
    effect the totalf, and only changes the iterpws() function.

    """
    def __init__(self, pass_file, max_pass_len=40, min_pass_len=1):
        self.fbasename = os.path.basename(pass_file).split('.',1)[0]
        _dirname = '{}/eff_data/'.format(pass_dir)
        if not os.path.exists(_dirname):
            os.makedirs(_dirname)

        self._max_pass_len = max_pass_len
        self._min_pass_len = min_pass_len
        self._file_trie = os.path.join(_dirname, self.fbasename + '.trie')
        self._file_freq = os.path.join(_dirname, self.fbasename + '.npz')
        self._T, self._freq_list, self._totalf = None, None, None
        if os.path.exists(self._file_trie) and os.path.exists(self._file_freq):
            self.load_data()
        else:
            self.create_data_structure(pass_file)
        assert self._T, "Could not initialize the trie."

    def create_data_structure(self, pass_file):
        # Record trie, Slow, and not memory efficient
        # self._T = marisa_trie.RecordTrie(
        #     '<II', ((unicode(w), (c,))
        #             for i, (w,c) in
        #     enumerate(passwords.open_get_line(pass_file)))
        # )
        tmp_dict = {w: c for w,c in open_get_line(pass_file)}
        self._T = marisa_trie.Trie(tmp_dict.keys())
        self._freq_list = np.zeros(len(self._T), dtype=int)
        for k in self._T.iterkeys():
            self._freq_list[self._T.key_id(k)] = tmp_dict[k]
        self._T.save(self._file_trie)
        self._totalf = self._freq_list.sum()
        np.savez_compressed(
            self._file_freq,
            freq=self._freq_list,
            fsum=self._totalf
        )

    def sample_pws(self, n, asperdist=True):
        """Returns n passwords sampled from this password dataset.  if
        asperdist is True, then returns the password sampled according
        the password histogram distribution (with
        replacement). Passwords are always sampled with replacement.

        TODO: The sample users, instead of passwords perse.
        """
        if asperdist:
            sample = np.random.choice(
                self._freq_list.shape[0], size=n, p=self._freq_list/self._totalf
            )
        else:
            sample = np.random.choice(len(self._T), size=n)
        return (self._T.restore_key(i) for i in sample)

    def load_data(self):
        self._T = marisa_trie.Trie()
        self._T.load(self._file_trie)
        np_f = np.load(self._file_freq)
        self._freq_list, self._totalf = np_f['freq'], np_f['fsum']

    def totalf(self):
        return self._totalf

    def pw2id(self, pw):
        try:
            return self._T.key_id(pw)
        except KeyError:
            return -1
        except UnicodeDecodeError as e:
            print(repr(pw), e)
            raise ValueError(e)

    def id2pw(self, _id):
        try:
            return self._T.restore_key(_id)
        except KeyError:
            return ''

    def prob(self, pw):
        return self.__getitem__(pw)/self._totalf

    def pw2freq(self, pw):
        try:
            return self._freq_list[self._T.key_id(pw)]
            # return self._T.get(unicode(pw), 0)
        except KeyError:
            return 0

    def id2freq(self, _id):
        _id = int(_id)
        try:
            return self._freq_list[_id]
        except ValueError:
            return 0

    def sumvalues(self, q=0):
        """Sum of top q passowrd frequencies
        """
        if q == 0:
            return self._totalf
        else:
            return -np.partition(-self._freq_list, q)[:q].sum()

    def iterpws(self, n):
        """
        Returns passwords in order of their frequencies.
        @n: The numebr of passwords to return
        Return: pwid, password, frequency
        Every password is assigned an uniq id, for efficient access.
        """
        for _id in np.argsort(self._freq_list)[::-1][:n]:
            pw = self._T.restore_key(_id)
            if self._min_pass_len <= len(pw) <= self._max_pass_len:
                yield _id, pw, self._freq_list[_id]

    def justiter(self):
        for w, _id in self._T.iteritems():
            yield _id, w, self._freq_list[_id]

    def keys(self):
        return self._T.iterkeys()

    def values(self):
        return self._freq_list

    def __iter__(self):
        for _id in np.argsort(self._freq_list)[::-1]:
            yield _id, self._freq_list[_id]

    def __getitem__(self, k):
        if isinstance(k, int):
            return self._freq_list[k]
        if isinstance(k, str):
            return self._freq_list[self.pw2id(k)]
        raise TypeError("_id is wrong type ({}) expects str or int"
                        .format(type(k)))

    def __len__(self):
        return self._freq_list.shape[0]


import unittest
class TestPasswords(unittest.TestCase):
    def test_pw2freq(self):
        passwords = Passwords(
            os.path.expanduser('~/passwords/rockyou-withcount.txt.bz2')
        )
        for pw, f in {'michelle': 12714, 'george': 4749,
                      'familia': 1975, 'honeybunny': 242,
                      'asdfasdf2wg': 0, '  234  adsf': 0}.items():
            pw = pw
            self.assertEqual(passwords.pw2freq(pw), f)

    def test_getallgroups(self):
        for inp, res in [(
                [1,2,3], set([
                    (1,), (2,), (3,), (1,2), (2,3), (1,3), (1,2,3)])
        )]:
            res1 = set(getallgroups(inp))
            self.assertEqual(res1, res)


if __name__ == "__main__":
    # print(list(getallgroups([1,2,3,4,5,6,7,8,9], 5)))
    unittest.main()
