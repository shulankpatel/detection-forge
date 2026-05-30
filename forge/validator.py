# forge/validator.py
from __future__ import annotations
import fnmatch
import re

def _match_value(actual, expected, modifier: str | None) -> bool:
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if modifier == "contains":
        return e.lower() in a.lower()
    if modifier == "startswith":
        return a.lower().startswith(e.lower())
    if modifier == "endswith":
        return a.lower().endswith(e.lower())
    if modifier == "re":
        return re.search(e, a) is not None
    if "*" in e or "?" in e:
        return fnmatch.fnmatch(a.lower(), e.lower())
    return a.lower() == e.lower()

def _eval_selection(selection, event: dict) -> bool:
    if isinstance(selection, list):
        return any(_eval_selection(s, event) for s in selection)
    for key, expected in selection.items():
        field, _, modifier = key.partition("|")
        actual = event.get(field)
        if isinstance(expected, list):
            ok = any(_match_value(actual, v, modifier or None) for v in expected)
        else:
            ok = _match_value(actual, expected, modifier or None)
        if not ok:
            return False
    return True

# --- condition parser (recursive descent over a tokenized condition string) ---

def _tokenize(condition: str) -> list[str]:
    return re.findall(r"\(|\)|\w+\*?|\*", condition)

class _Parser:
    def __init__(self, tokens, results):
        self.t = tokens
        self.i = 0
        self.results = results  # {selection_name: bool}

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        return self._or()

    def _or(self):
        val = self._and()
        while self.peek() == "or":
            self.next()
            val = self._and() or val
        return val

    def _and(self):
        val = self._not()
        while self.peek() == "and":
            self.next()
            rhs = self._not()
            val = val and rhs
        return val

    def _not(self):
        if self.peek() == "not":
            self.next()
            return not self._not()
        return self._atom()

    def _atom(self):
        tok = self.peek()
        if tok == "(":
            self.next()
            val = self._or()
            self.next()  # consume ')'
            return val
        if tok in ("all", "1", "any"):
            return self._aggregation()
        self.next()
        return self.results.get(tok, False)

    def _aggregation(self):
        quant = self.next()  # 'all' | '1' | 'any'
        self.next()          # 'of'
        target = self.next() # 'them' | 'pattern*'
        if target == "them":
            names = list(self.results)
        else:
            names = [n for n in self.results if fnmatch.fnmatch(n, target)]
        vals = [self.results[n] for n in names]
        return all(vals) if quant == "all" else any(vals)

def matches(detection: dict, event: dict) -> bool:
    condition = detection["condition"]
    results = {
        name: _eval_selection(sel, event)
        for name, sel in detection.items()
        if name != "condition"
    }
    return _Parser(_tokenize(condition), results).parse()
