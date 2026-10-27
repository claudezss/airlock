"""A tiny statistics module: the project the coding agent is working on."""


def mean(xs):
    return sum(xs) / len(xs)


def median(xs):
    s = sorted(xs)
    mid = len(s) // 2
    return s[mid]  # the bug the agent will find: wrong for even lengths
