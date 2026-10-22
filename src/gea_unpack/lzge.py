"""Bounded Python LZGE decoder, adapted from Gentee's MIT-licensed 2009 source.

Copyright (c) 2006-2009 The Gentee Group. See third_party/GENTEE-LICENSE.
Format reference: https://www.gentee.com/source/lib/gea/geacommon_g.htm
"""

RANGE_BITS = [
    0,
    0,
    0,
    1,
    1,
    2,
    2,
    2,
    3,
    3,
    4,
    4,
    5,
    5,
    6,
    6,
    7,
    7,
    8,
    8,
    9,
    9,
    10,
    10,
    11,
    11,
    12,
    12,
    13,
    13,
    14,
    14,
    15,
    15,
    16,
    16,
] + [17] * 14
LENGTH_BITS = [0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6]


class Bits:
    def __init__(self, raw):
        self.raw = raw
        self.position = 0

    def bit(self):
        if self.position >= len(self.raw) * 8:
            raise ValueError("Truncated LZGE bits")
        value = (self.raw[self.position // 8] >> (7 - self.position % 8)) & 1
        self.position += 1
        return value

    def number(self, n):
        if not 0 <= n <= 32:
            raise ValueError("LZGE numeric width outside bound")
        return sum(self.bit() << i for i in range(n))


def normalize(lengths):
    pending = {}
    nodes = [i for i in range(len(lengths))]
    depths = list(lengths)
    i = 0
    while i < len(nodes):
        depth = depths[i]
        if depth:
            if not 1 <= depth <= 64:
                raise ValueError("LZGE tree depth outside bound")
            if depth in pending:
                left = pending.pop(depth)
                node = (nodes[left], nodes[i])
                if depth == 1:
                    if pending or any(depths[j] for j in range(i + 1, len(depths))):
                        raise ValueError("Oversubscribed LZGE tree")
                    return node
                nodes.append(node)
                depths.append(depth - 1)
            else:
                pending[depth] = i
        depths[i] = 0
        i += 1
        if len(nodes) > 4096:
            raise ValueError("LZGE tree exceeds node bound")
    if len(pending) == 1 and 1 in pending:
        return (nodes[pending[1]], None)
    raise ValueError("Incomplete or empty LZGE tree")


def symbol(bits, root):
    node = root
    for _ in range(65):
        if isinstance(node, int):
            return node
        node = node[bits.bit()]
        if node is None:
            raise ValueError("Invalid unary LZGE code")
    raise ValueError("LZGE tree traversal outside bound")


def tree(bits, count, previous, fixed=False):
    width = bits.number(2 if count < 32 else 3) + 1
    minimum = bits.number(width)
    maximum = minimum + bits.number(width)
    if minimum > 64 or maximum > 64:
        raise ValueError("LZGE declared depth outside bound")
    if fixed:
        values = [bits.number(width) for _ in range(count)]
    else:
        pre = tree(bits, 20, [0] * 20, True)
        values = []
        while len(values) < count:
            code = symbol(bits, pre)
            if code <= 15:
                values.append(code)
            elif code == 19:
                values.append(bits.number(width))
            else:
                run = bits.number({16: 2, 17: 4, 18: 6}[code]) + {16: 4, 17: 8, 18: 24}[code]
                if len(values) + run > count:
                    raise ValueError("LZGE zero run exceeds alphabet")
                values.extend([0] * run)
    lengths = []
    for i, value in enumerate(values):
        old = previous[i]
        previous[i] = 0
        if value <= 15:
            value = (value + old) % 16
            previous[i] = value
        length = value + minimum - 1 if value else 0
        if length > maximum:
            raise ValueError("LZGE code exceeds declared maximum")
        lengths.append(length)
    return normalize(lengths)


def decode(raw, size, history=b"", maximum=8 * 1024 * 1024):
    if not 0 < size <= maximum or len(history) > maximum or len(raw) > maximum * 2:
        raise ValueError("LZGE input/output/history exceeds bound")
    total = size + len(history)
    maxbit = min(21, total.bit_length())
    maxoff = (1 << maxbit) - 1
    ranges = [0, 0, 0]
    end = 2
    for n in RANGE_BITS[3:]:
        ranges.append(end)
        end += 1 << n
        if end - 1 >= maxoff:
            break
    lengths = []
    end = 2
    length_bits = LENGTH_BITS + [maxbit]
    for n in length_bits:
        lengths.append(end)
        end += 1 << n
    count = 256 + 18 * len(ranges) + 1
    previous = [0] * count
    bits = Bits(raw)
    out = bytearray(history)
    recent = [3, 4, 5]
    while len(out) < total:
        root = tree(bits, count, previous)
        for _ in range(10000):
            if len(out) == total:
                break
            value = symbol(bits, root)
            if value < 256:
                out.append(value)
                continue
            code = value - 256
            if code == 18 * len(ranges):
                slot = 18
                footer = 0
            else:
                slot = code % 18
                footer = code // 18
            length = bits.number(length_bits[slot]) + lengths[slot]
            if slot == 18:
                offset = bits.number(maxbit)
            else:
                offset = bits.number(RANGE_BITS[footer]) + ranges[footer]
                if footer == 0:
                    offset = recent[0]
                elif footer == 1:
                    offset = recent[1]
                    recent = [offset, recent[0], recent[2]]
                else:
                    if footer == 2:
                        offset = recent[2]
                    recent = [offset, recent[0], recent[1]]
            if not 0 < offset <= len(out) or len(out) + length > total:
                raise ValueError("LZGE match outside decoded history/output")
            for _ in range(length):
                out.append(out[-offset])
    return bytes(out[len(history) :]), {
        "bits_consumed": bits.position,
        "bytes_read": (bits.position + 7) // 8,
        "original_decoder_consumption": bits.position // 8 + 1,
        "output_bytes": size,
    }
